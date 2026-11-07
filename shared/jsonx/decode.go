// Package jsonx decodes untrusted JSON strictly and within bounds: it rejects
// duplicate object keys (also under Unicode case folding where the target is a
// struct), unknown fields (matched exactly, never case-insensitively), invalid
// UTF-8, lone surrogate escapes, trailing data, oversized bodies and excessive
// nesting. Errors never echo input content.
package jsonx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"unicode"
	"unicode/utf8"
)

// Limits bounds the size and nesting depth of a decoded document.
type Limits struct {
	// MaxBytes is the largest accepted body, in bytes.
	MaxBytes int64
	// MaxDepth is the deepest accepted nesting of arrays and objects.
	MaxDepth int
	// AllowUnknownFields makes members that bind to no struct field be
	// skipped instead of refused (RFC 7519 section 4: unknown claims are
	// ignored). Skipped members are still checked for size, depth, encoding
	// and duplicate keys. A key that matches a known field only under case
	// folding is still refused with ErrUnknownField, never bound.
	AllowUnknownFields bool
}

// DefaultLimits is a conservative default for API bodies.
var DefaultLimits = Limits{MaxBytes: 1 << 20, MaxDepth: 32}

// Sentinel errors. They carry no input content.
var (
	ErrTooLarge     = errors.New("jsonx: document too large")
	ErrTooDeep      = errors.New("jsonx: document nested too deeply")
	ErrDuplicateKey = errors.New("jsonx: duplicate object key")
	ErrUnknownField = errors.New("jsonx: unknown field")
	ErrTrailingData = errors.New("jsonx: trailing data after document")
	ErrInvalidJSON  = errors.New("jsonx: invalid JSON")
	ErrRead         = errors.New("jsonx: read failed")
)

// DecodeStrict reads one JSON document from r into v, which must be a non-nil
// pointer. v is overwritten only on success; on error it is left untouched.
func DecodeStrict(r io.Reader, v any, lim Limits) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("%w: target must be a non-nil pointer", ErrInvalidJSON)
	}
	data, err := readBounded(r, lim)
	if err != nil {
		return err
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("%w: invalid UTF-8", ErrInvalidJSON)
	}
	if !surrogatesPaired(data) {
		return fmt.Errorf("%w: lone surrogate escape", ErrInvalidJSON)
	}

	p := &parser{dec: json.NewDecoder(bytes.NewReader(data)), maxDepth: lim.MaxDepth, allowUnknown: lim.AllowUnknownFields}
	p.dec.UseNumber()
	if err := p.document(rv.Elem().Type()); err != nil {
		return err
	}

	tmp := reflect.New(rv.Elem().Type())
	dec := json.NewDecoder(bytes.NewReader(data))
	if !lim.AllowUnknownFields {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(tmp.Interface()); err != nil {
		return ErrInvalidJSON
	}
	rv.Elem().Set(tmp.Elem())
	return nil
}

// readBounded validates lim and reads at most MaxBytes of r.
func readBounded(r io.Reader, lim Limits) ([]byte, error) {
	if lim.MaxBytes < 0 || lim.MaxBytes == math.MaxInt64 || lim.MaxDepth < 1 {
		return nil, fmt.Errorf("%w: invalid limits", ErrInvalidJSON)
	}
	data, err := io.ReadAll(io.LimitReader(r, lim.MaxBytes+1))
	if err != nil {
		return nil, ErrRead
	}
	if int64(len(data)) > lim.MaxBytes {
		return nil, ErrTooLarge
	}
	return data, nil
}

// surrogatesPaired reports whether every \u surrogate escape inside a string is
// part of a valid high+low pair. Malformed escapes are left to the decoder.
func surrogatesPaired(b []byte) bool {
	inStr := false
	for i := 0; i < len(b); i++ {
		switch {
		case !inStr:
			inStr = b[i] == '"'
		case b[i] == '"':
			inStr = false
		case b[i] == '\\':
			if i+1 < len(b) && b[i+1] == 'u' {
				ok, n := checkEscape(b, i)
				if !ok {
					return false
				}
				i += n
			} else {
				i++
			}
		}
	}
	return true
}

// checkEscape inspects the \uXXXX at b[i:]; it returns whether it is acceptable
// and how many extra bytes to skip.
func checkEscape(b []byte, i int) (bool, int) {
	r, ok := hex4(b, i+2)
	switch {
	case !ok:
		return true, 1
	case isLow(r):
		return false, 0
	case isHigh(r):
		if hasLowAt(b, i+6) {
			return true, 11
		}
		return false, 0
	}
	return true, 5
}

func isHigh(r rune) bool { return r >= 0xD800 && r <= 0xDBFF }
func isLow(r rune) bool  { return r >= 0xDC00 && r <= 0xDFFF }

// hasLowAt reports whether b[i:] starts with a \uXXXX low-surrogate escape.
func hasLowAt(b []byte, i int) bool {
	if i+1 >= len(b) || b[i] != '\\' || b[i+1] != 'u' {
		return false
	}
	lo, ok := hex4(b, i+2)
	return ok && isLow(lo)
}

func hex4(b []byte, i int) (rune, bool) {
	if i+4 > len(b) {
		return 0, false
	}
	var r rune
	for _, c := range b[i : i+4] {
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return r, true
}

// parser walks the token stream alongside the decode target's type.
type parser struct {
	dec          *json.Decoder
	maxDepth     int
	allowUnknown bool
}

func (p *parser) document(t reflect.Type) error {
	if err := p.value(t, 0); err != nil {
		return err
	}
	if _, err := p.dec.Token(); err != io.EOF {
		return ErrTrailingData
	}
	return nil
}

// value consumes one value; depth is the number of containers already open.
func (p *parser) value(t reflect.Type, depth int) error {
	tok, err := p.dec.Token()
	if err != nil {
		return ErrInvalidJSON
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if depth+1 > p.maxDepth {
		return ErrTooDeep
	}
	if d == '{' {
		return p.object(t, depth+1)
	}
	return p.array(t, depth+1)
}

func (p *parser) array(t reflect.Type, depth int) error {
	var elem reflect.Type
	if t = resolve(t); t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
		elem = t.Elem()
	}
	for p.dec.More() {
		if err := p.value(elem, depth); err != nil {
			return err
		}
	}
	return p.closer()
}

func (p *parser) closer() error {
	if _, err := p.dec.Token(); err != nil {
		return ErrInvalidJSON
	}
	return nil
}

func (p *parser) object(t reflect.Type, depth int) error {
	fields, mapElem := objectShape(resolve(t))
	seen := map[string]struct{}{}
	for p.dec.More() {
		key, err := p.key()
		if err != nil {
			return err
		}
		id := key
		if fields != nil {
			id = foldKey(key)
		}
		if _, dup := seen[id]; dup {
			return ErrDuplicateKey
		}
		seen[id] = struct{}{}
		elem, err := elemType(fields, mapElem, key, p.allowUnknown)
		if err != nil {
			return err
		}
		if err := p.value(elem, depth); err != nil {
			return err
		}
	}
	return p.closer()
}

func (p *parser) key() (string, error) {
	tok, err := p.dec.Token()
	key, ok := tok.(string)
	if err != nil || !ok {
		return "", ErrInvalidJSON
	}
	return key, nil
}

// objectShape returns the exact field table for structs or the element type
// for maps; both are nil when the target says nothing about the keys.
func objectShape(t reflect.Type) (map[string]reflect.Type, reflect.Type) {
	switch {
	case t == nil:
		return nil, nil
	case t.Kind() == reflect.Struct:
		return structFields(t), nil
	case t.Kind() == reflect.Map:
		return nil, t.Elem()
	}
	return nil, nil
}

// elemType is the type of the value under key; struct keys must match a field
// name exactly. With allowUnknown, a key that matches no field even under case
// folding is skipped (nil type); one that matches only under folding, which
// encoding/json would bind, is refused.
func elemType(fields map[string]reflect.Type, mapElem reflect.Type, key string, allowUnknown bool) (reflect.Type, error) {
	if fields == nil {
		return mapElem, nil
	}
	if ft, known := fields[key]; known {
		return ft, nil
	}
	if !allowUnknown || foldsToField(fields, key) {
		return nil, ErrUnknownField
	}
	return nil, nil
}

// foldsToField reports whether key equals a field name under case folding.
func foldsToField(fields map[string]reflect.Type, key string) bool {
	k := foldKey(key)
	for name := range fields {
		if foldKey(name) == k {
			return true
		}
	}
	return false
}

// foldKey maps a key to a canonical form shared by all keys that are equal
// under Unicode simple case folding (the relation strings.EqualFold uses).
func foldKey(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		m := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < m {
				m = f
			}
		}
		out = append(out, m)
	}
	return string(out)
}

var unmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

// resolve strips pointers; it returns nil (no type knowledge) for interfaces
// and for types that decode themselves.
func resolve(t reflect.Type) reflect.Type {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() == reflect.Interface ||
		t.Implements(unmarshalerType) || reflect.PointerTo(t).Implements(unmarshalerType) {
		return nil
	}
	return t
}
