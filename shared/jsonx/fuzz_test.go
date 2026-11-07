package jsonx_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aleogr/iam/shared/jsonx"
)

var sentinels = []error{
	jsonx.ErrTooLarge, jsonx.ErrTooDeep, jsonx.ErrDuplicateKey, jsonx.ErrUnknownField,
	jsonx.ErrTrailingData, jsonx.ErrInvalidJSON, jsonx.ErrRead,
}

func isSentinel(err error) bool {
	for _, s := range sentinels {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}

func addSeeds(f *testing.F) {
	for _, s := range []string{
		`{"a":1,"s":"x","i":{"n":2}}`, `{"a":1,"a":2}`, `{"a":1,"A":2}`, `{"A":1}`, `{"zzz":1}`,
		`{"a":1,"a":2}`, `{"s":"\ud800"}`, "{\"s\":\"\xff\"}", `[[[[[[[[[[[[`,
		strings.Repeat("[", 9) + strings.Repeat("]", 9), `[{"a":1,"a":2}]`, `[{"a":1},{"a":2}]`,
		`{"a":1}{"a":2}`, ``, `null`, "{\"K\":1}",
	} {
		f.Add([]byte(s))
	}
}

func FuzzDecodeStrict(f *testing.F) {
	addSeeds(f)
	lim := jsonx.Limits{MaxBytes: 256, MaxDepth: 8}
	f.Fuzz(func(t *testing.T, data []byte) {
		var got doc
		err := jsonx.DecodeStrict(bytes.NewReader(data), &got, lim)
		if err != nil {
			if !isSentinel(err) {
				t.Fatalf("error is not a sentinel: %v", err)
			}
			if got != (doc{}) {
				t.Fatalf("value not zero after error %v: %+v", err, got)
			}
			return
		}
		// Accepted into a struct: plain encoding/json must agree, and the
		// document must satisfy the same independent oracle as the any target.
		var again doc
		if json.Unmarshal(data, &again) != nil || again != got {
			t.Fatalf("accepted input disagrees with encoding/json")
		}
		oracle(t, data, lim.MaxDepth, false)
	})
}

// With AllowUnknownFields, accepted input must decode exactly as plain
// encoding/json does (no member bound case-insensitively), and anything the
// strict mode accepts must be accepted with the same value.
func FuzzDecodeStrictAllowUnknown(f *testing.F) {
	addSeeds(f)
	lim := jsonx.Limits{MaxBytes: 256, MaxDepth: 8, AllowUnknownFields: true}
	strict := jsonx.Limits{MaxBytes: 256, MaxDepth: 8}
	f.Fuzz(func(t *testing.T, data []byte) {
		var got, strictGot doc
		err := jsonx.DecodeStrict(bytes.NewReader(data), &got, lim)
		strictErr := jsonx.DecodeStrict(bytes.NewReader(data), &strictGot, strict)
		if err != nil {
			if !isSentinel(err) {
				t.Fatalf("error is not a sentinel: %v", err)
			}
			if got != (doc{}) {
				t.Fatalf("value not zero after error %v: %+v", err, got)
			}
			if strictErr == nil {
				t.Fatalf("strict mode accepts what the lenient mode refuses: %v", err)
			}
			return
		}
		if strictErr == nil && strictGot != got {
			t.Fatalf("modes disagree on the value")
		}
		var again doc
		if json.Unmarshal(data, &again) != nil || again != got {
			t.Fatalf("accepted input disagrees with encoding/json")
		}
		oracle(t, data, lim.MaxDepth, false)
	})
}

func FuzzDecodeStrictAny(f *testing.F) {
	addSeeds(f)
	lim := jsonx.Limits{MaxBytes: 256, MaxDepth: 8}
	f.Fuzz(func(t *testing.T, data []byte) {
		var got any
		err := jsonx.DecodeStrict(bytes.NewReader(data), &got, lim)
		if err != nil {
			if !isSentinel(err) {
				t.Fatalf("error is not a sentinel: %v", err)
			}
			if got != nil {
				t.Fatalf("value not zero after error %v", err)
			}
			return
		}
		oracle(t, data, lim.MaxDepth, true)
	})
}

// oracle independently re-checks accepted input: depth within the limit and,
// for any-typed targets, no exactly duplicated keys in any object. It is an
// iterative token scan, unlike the production recursive parser.
func oracle(t *testing.T, data []byte, maxDepth int, checkDup bool) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	var st []oracleFrame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("oracle: accepted input fails tokenizing: %v", err)
		}
		st = oracleStep(t, st, tok, maxDepth, checkDup)
	}
}

// oracleFrame is an open container; keys is nil for arrays.
type oracleFrame struct {
	keys    map[string]bool
	wantKey bool
}

func oracleStep(t *testing.T, st []oracleFrame, tok json.Token, maxDepth int, checkDup bool) []oracleFrame {
	t.Helper()
	if d, ok := tok.(json.Delim); ok {
		return oracleDelim(t, st, d, maxDepth)
	}
	if key, ok := tok.(string); ok && len(st) > 0 && st[len(st)-1].wantKey {
		top := &st[len(st)-1]
		if checkDup && top.keys[key] {
			t.Fatalf("oracle: duplicate key accepted")
		}
		top.keys[key], top.wantKey = true, false
		return st
	}
	oracleValueDone(st)
	return st
}

// oracleValueDone marks a value as consumed so the enclosing object wants a key.
func oracleValueDone(st []oracleFrame) {
	if n := len(st); n > 0 && st[n-1].keys != nil {
		st[n-1].wantKey = true
	}
}

func oracleDelim(t *testing.T, st []oracleFrame, d json.Delim, maxDepth int) []oracleFrame {
	t.Helper()
	if d == '}' || d == ']' {
		st = st[:len(st)-1]
		oracleValueDone(st)
		return st
	}
	if len(st) >= maxDepth {
		t.Fatalf("oracle: depth exceeds %d", maxDepth)
	}
	f := oracleFrame{}
	if d == '{' {
		f = oracleFrame{keys: map[string]bool{}, wantKey: true}
	}
	return append(st, f)
}
