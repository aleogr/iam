package jsonx_test

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/aleogr/iam/shared/jsonx"
)

type inner struct {
	N int `json:"n"`
}

type doc struct {
	A int    `json:"a"`
	S string `json:"s"`
	I inner  `json:"i"`
}

func TestDecodeStrict(t *testing.T) {
	lim := jsonx.Limits{MaxBytes: 64, MaxDepth: 32}

	tests := []struct {
		name string
		in   string
		lim  jsonx.Limits
		want error
	}{
		{"valid", `{"a":1,"s":"x","i":{"n":2}}`, lim, nil},
		{"valid with whitespace", " {\"a\":1}\n", lim, nil},
		{"duplicate top level", `{"a":1,"a":2}`, lim, jsonx.ErrDuplicateKey},
		{"duplicate nested", `{"i":{"n":1,"n":2}}`, lim, jsonx.ErrDuplicateKey},
		{"duplicate in array element", `{"i":[{"n":1,"n":2}]}`, lim, jsonx.ErrDuplicateKey},
		{"unknown field", `{"zzz":1}`, lim, jsonx.ErrUnknownField},
		{"too large", `{"s":"` + strings.Repeat("x", 64) + `"}`, lim, jsonx.ErrTooLarge},
		{"exactly max bytes", `{"s":"` + strings.Repeat("x", 64-8) + `"}`, lim, nil},
		{"two values", `{"a":1}{"a":2}`, lim, jsonx.ErrTrailingData},
		{"trailing garbage", `{"a":1} x`, lim, jsonx.ErrTrailingData},
		{"syntax", `{"a":`, lim, jsonx.ErrInvalidJSON},
		{"empty", ``, lim, jsonx.ErrInvalidJSON},
		{"type mismatch", `{"a":"str"}`, lim, jsonx.ErrInvalidJSON},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got doc
			err := jsonx.DecodeStrict(strings.NewReader(tc.in), &got, tc.lim)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if err != nil && got != (doc{}) {
				t.Fatalf("value not zero after error: %+v", got)
			}
		})
	}
}

func TestDecodeStrictValue(t *testing.T) {
	var got doc
	if err := jsonx.DecodeStrict(strings.NewReader(`{"a":1,"s":"x","i":{"n":2}}`), &got, jsonx.DefaultLimits); err != nil {
		t.Fatal(err)
	}
	if got != (doc{A: 1, S: "x", I: inner{N: 2}}) {
		t.Fatalf("unexpected value %+v", got)
	}
}

func TestDecodeStrictLeavesValueZeroOnLateError(t *testing.T) {
	// The first field decodes fine; the unknown one fails afterwards.
	var got doc
	err := jsonx.DecodeStrict(strings.NewReader(`{"a":1,"zzz":2}`), &got, jsonx.DefaultLimits)
	if !errors.Is(err, jsonx.ErrUnknownField) {
		t.Fatalf("want ErrUnknownField, got %v", err)
	}
	if got != (doc{}) {
		t.Fatalf("value not zero: %+v", got)
	}
}

func TestDecodeStrictRejectsBadTarget(t *testing.T) {
	var d doc
	for _, v := range []any{nil, d, (*doc)(nil)} {
		if err := jsonx.DecodeStrict(strings.NewReader(`{}`), v, jsonx.DefaultLimits); err == nil {
			t.Fatalf("want error for target %T", v)
		}
	}
}

func TestErrorsDoNotEchoInput(t *testing.T) {
	const secret = "s3cr3t-token-value"
	inputs := []string{
		`{"` + secret + `":1}`,
		`{"a":1,"a":2,"` + secret + `":1}`,
		`{"a":"` + secret + `"}`,
		`{"a":1} ` + secret,
		`{"s":` + secret + `}`,
	}
	for _, in := range inputs {
		var d doc
		err := jsonx.DecodeStrict(strings.NewReader(in), &d, jsonx.DefaultLimits)
		if err == nil {
			t.Fatalf("want error for %q", in)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error echoes input: %v", err)
		}
	}
}

func TestDecodeStrictDepthAndSiblings(t *testing.T) {
	nest := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	lim := jsonx.Limits{MaxBytes: 1 << 10, MaxDepth: 32}
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"depth 32", nest(32), nil},
		{"depth 33", nest(33), jsonx.ErrTooDeep},
		{"depth 33 in object", strings.Repeat(`{"k":`, 33) + "1" + strings.Repeat("}", 33), jsonx.ErrTooDeep},
		{"same key in sibling objects", `[{"a":1},{"a":2}]`, nil},
		{"same key in parent and child", `{"a":{"a":1}}`, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var v any
			if err := jsonx.DecodeStrict(strings.NewReader(tc.in), &v, lim); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

type lower struct {
	A int `json:"a"`
	K int `json:"k"`
	S int `json:"s"`
}

type embedded struct {
	Lower lower   `json:"l"`
	List  []lower `json:"list"`
	Skip  int     `json:"-"`
	Plain int
	Opt   int `json:"opt,omitempty"`
	base
}

type base struct {
	Inherited int `json:"inherited"`
}

func TestDecodeStrictCaseSmuggling(t *testing.T) {
	const kelvin, longS = "K", "ſ"
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"exact duplicate pair", `{"a":1,"A":2}`, jsonx.ErrDuplicateKey},
		{"case only key", `{"A":1}`, jsonx.ErrUnknownField},
		{"kelvin only", `{"` + kelvin + `":1}`, jsonx.ErrUnknownField},
		{"kelvin collides", `{"k":1,"` + kelvin + `":2}`, jsonx.ErrDuplicateKey},
		{"long s only", `{"` + longS + `":1}`, jsonx.ErrUnknownField},
		{"long s collides", `{"s":1,"` + longS + `":2}`, jsonx.ErrDuplicateKey},
		{"escaped key duplicates", `{"a":1,"\u0061":2}`, jsonx.ErrDuplicateKey},
		{"escaped key accepted", `{"\u0061":1}`, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got lower
			err := jsonx.DecodeStrict(strings.NewReader(tc.in), &got, jsonx.DefaultLimits)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if err != nil && got != (lower{}) {
				t.Fatalf("value not zero: %+v", got)
			}
		})
	}
}

func TestDecodeStrictNestedTypes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"valid", `{"l":{"a":1},"list":[{"a":1},{"a":2}],"Plain":3,"opt":4,"inherited":5}`, nil},
		{"nested case", `{"l":{"A":1}}`, jsonx.ErrUnknownField},
		{"nested dup case", `{"l":{"a":1,"A":2}}`, jsonx.ErrDuplicateKey},
		{"slice element case", `{"list":[{"a":1},{"A":2}]}`, jsonx.ErrUnknownField},
		{"slice element dup", `{"list":[{"a":1,"a":2}]}`, jsonx.ErrDuplicateKey},
		{"outer case", `{"L":{}}`, jsonx.ErrUnknownField},
		{"ignored field name", `{"Skip":1}`, jsonx.ErrUnknownField},
		{"untagged field exact", `{"plain":1}`, jsonx.ErrUnknownField},
		{"embedded promoted", `{"inherited":1}`, nil},
		{"embedded promoted case", `{"Inherited":1}`, jsonx.ErrUnknownField},
		{"unknown nested", `{"l":{"zzz":1}}`, jsonx.ErrUnknownField},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got embedded
			err := jsonx.DecodeStrict(strings.NewReader(tc.in), &got, jsonx.DefaultLimits)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestDecodeStrictMapAndAnyKeepCaseDistinctKeys(t *testing.T) {
	var m map[string]int
	if err := jsonx.DecodeStrict(strings.NewReader(`{"a":1,"A":2}`), &m, jsonx.DefaultLimits); err != nil {
		t.Fatal(err)
	}
	if m["a"] != 1 || m["A"] != 2 {
		t.Fatalf("unexpected map %v", m)
	}
	var a any
	if err := jsonx.DecodeStrict(strings.NewReader(`{"a":1,"A":2}`), &a, jsonx.DefaultLimits); err != nil {
		t.Fatal(err)
	}
	if err := jsonx.DecodeStrict(strings.NewReader(`{"a":1,"a":2}`), &m, jsonx.DefaultLimits); !errors.Is(err, jsonx.ErrDuplicateKey) {
		t.Fatalf("want ErrDuplicateKey, got %v", err)
	}
}

func TestDecodeStrictInvalidEncoding(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"invalid utf-8", "{\"s\":\"\xff\"}"},
		{"lone high surrogate", `{"s":"\ud800"}`},
		{"high surrogate then text", `{"s":"\ud800x"}`},
		{"high surrogate then non-low", `{"s":"\ud800A"}`},
		{"lone low surrogate", `{"s":"\udc00"}`},
		{"low then high", `{"s":"\udc00\ud800"}`},
		{"lone surrogate in key", `{"\ud800":1}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var v any
			if err := jsonx.DecodeStrict(strings.NewReader(tc.in), &v, jsonx.DefaultLimits); !errors.Is(err, jsonx.ErrInvalidJSON) {
				t.Fatalf("want ErrInvalidJSON, got %v", err)
			}
		})
	}
	var v any
	ok := `{"s":"😀 \\ud800 \\\\"}`
	if err := jsonx.DecodeStrict(strings.NewReader(ok), &v, jsonx.DefaultLimits); err != nil {
		t.Fatalf("valid pair/escaped backslash rejected: %v", err)
	}
}

type endless struct{}

func (endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

type failing struct{}

func (failing) Read([]byte) (int, error) { return 0, errors.New("disk secret-path") }

func TestDecodeStrictLimitsAndReaders(t *testing.T) {
	lim := jsonx.Limits{MaxBytes: 10, MaxDepth: 4}
	var v any
	exact := "{}" + strings.Repeat(" ", 8)
	if err := jsonx.DecodeStrict(strings.NewReader(exact), &v, lim); err != nil {
		t.Fatalf("exactly MaxBytes: %v", err)
	}
	if err := jsonx.DecodeStrict(strings.NewReader(exact+" "), &v, lim); !errors.Is(err, jsonx.ErrTooLarge) {
		t.Fatalf("MaxBytes+1: %v", err)
	}
	if err := jsonx.DecodeStrict(endless{}, &v, lim); !errors.Is(err, jsonx.ErrTooLarge) {
		t.Fatalf("endless: %v", err)
	}
	err := jsonx.DecodeStrict(failing{}, &v, lim)
	if !errors.Is(err, jsonx.ErrRead) || strings.Contains(err.Error(), "secret-path") {
		t.Fatalf("read error: %v", err)
	}
	for _, bad := range []jsonx.Limits{{MaxBytes: -1, MaxDepth: 1}, {MaxBytes: 1, MaxDepth: 0}, {MaxBytes: math.MaxInt64, MaxDepth: 1}} {
		if err := jsonx.DecodeStrict(strings.NewReader(`{}`), &v, bad); err == nil {
			t.Fatalf("limits %+v accepted", bad)
		}
	}
}

type inA struct {
	A int `json:"a"`
}

type tagEmb struct {
	X inA `json:"x"`
}

// outer field x shadows the embedded one.
type outerWins struct {
	tagEmb
	X struct {
		B int `json:"b"`
	} `json:"x"`
}

type taggedEmb struct {
	Name inA `json:"name"`
}

// both fields are tagged "name" at the same depth: ambiguous.
type eqDepth struct {
	taggedEmb
	untaggedName //nolint:govet // duplicate tag is the point of this fixture
}

type untaggedName struct {
	Name struct {
		Z int `json:"z"`
	} `json:"name"`
}

type ambiguousA struct {
	V inA `json:"v"`
}
type ambiguousB struct {
	V inA `json:"v"`
}
type ambiguous struct {
	ambiguousA
	ambiguousB     //nolint:govet // duplicate tag is the point of this fixture
	Other      int `json:"other"`
}

type taggedBeatsUntagged struct {
	pa
	pb
}
type pa struct {
	Name inA
}
type pb struct {
	N inA `json:"Name"`
}

func TestDecodeStrictEmbeddedDominance(t *testing.T) {
	check := func(t *testing.T, v any, in string, want error) {
		t.Helper()
		if err := jsonx.DecodeStrict(strings.NewReader(in), v, jsonx.DefaultLimits); !errors.Is(err, want) {
			t.Fatalf("%s: want %v, got %v", in, want, err)
		}
	}
	t.Run("outer wins and is strict", func(t *testing.T) {
		check(t, &outerWins{}, `{"x":{"b":1}}`, nil)
		check(t, &outerWins{}, `{"x":{"B":1}}`, jsonx.ErrUnknownField)
		check(t, &outerWins{}, `{"x":{"b":1,"B":2}}`, jsonx.ErrDuplicateKey)
		check(t, &outerWins{}, `{"x":{"a":1}}`, jsonx.ErrUnknownField)
	})
	t.Run("embedded loses to outer even with case smuggling", func(t *testing.T) {
		check(t, &outerWins{}, `{"x":{"a":1,"A":2}}`, jsonx.ErrUnknownField)
	})
	t.Run("tagged beats untagged at equal depth", func(t *testing.T) {
		check(t, &taggedBeatsUntagged{}, `{"Name":{"a":1}}`, nil)
		check(t, &taggedBeatsUntagged{}, `{"Name":{"A":1}}`, jsonx.ErrUnknownField)
		check(t, &taggedBeatsUntagged{}, `{"Name":{"a":1,"A":2}}`, jsonx.ErrDuplicateKey)
	})
	t.Run("ambiguous name is dropped", func(t *testing.T) {
		check(t, &ambiguous{}, `{"v":{"a":1}}`, jsonx.ErrUnknownField)
		check(t, &ambiguous{}, `{"other":1}`, nil)
		check(t, &eqDepth{}, `{"name":{"a":1}}`, jsonx.ErrUnknownField)
	})
}

func TestDecodeStrictAllowUnknownFields(t *testing.T) {
	const kelvin = "K"
	lim := jsonx.Limits{MaxBytes: 1 << 10, MaxDepth: 4, AllowUnknownFields: true}
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"unknown skipped", `{"l":{"a":1,"zzz":[1,{"q":2}]},"zzz":"x","inherited":5}`, nil},
		{"json dash never binds", `{"Skip":1}`, nil},
		{"unknown nested in slice", `{"list":[{"a":1,"new":true}]}`, nil},
		{"duplicate unknown", `{"zzz":1,"zzz":2}`, jsonx.ErrDuplicateKey},
		{"duplicate inside unknown", `{"zzz":{"q":1,"q":2}}`, jsonx.ErrDuplicateKey},
		{"case only key", `{"l":{"A":1}}`, jsonx.ErrUnknownField},
		{"kelvin only", `{"l":{"` + kelvin + `":1}}`, jsonx.ErrUnknownField},
		{"untagged case", `{"plain":1}`, jsonx.ErrUnknownField},
		{"promoted case", `{"Inherited":1}`, jsonx.ErrUnknownField},
		{"outer case", `{"L":{}}`, jsonx.ErrUnknownField},
		{"case duplicate", `{"l":{"a":1,"A":2}}`, jsonx.ErrDuplicateKey},
		{"too deep inside unknown", `{"zzz":[[[[1]]]]}`, jsonx.ErrTooDeep},
		{"bad utf8 inside unknown", "{\"zzz\":\"\xff\"}", jsonx.ErrInvalidJSON},
		{"lone surrogate inside unknown", `{"zzz":"\ud800"}`, jsonx.ErrInvalidJSON},
		{"trailing data", `{"zzz":1}{}`, jsonx.ErrTrailingData},
		{"too large", `{"zzz":"` + strings.Repeat("x", 1<<10) + `"}`, jsonx.ErrTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got embedded
			err := jsonx.DecodeStrict(strings.NewReader(tc.in), &got, lim)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if err != nil && !reflect.ValueOf(got).IsZero() {
				t.Fatalf("value not zero: %+v", got)
			}
		})
	}
}

func TestDecodeStrictAllowUnknownFieldsValue(t *testing.T) {
	lim := jsonx.Limits{MaxBytes: 1 << 10, MaxDepth: 4, AllowUnknownFields: true}
	var got embedded
	in := `{"l":{"a":7,"zzz":1},"list":[{"k":2,"new":0}],"zzz":"x","Plain":3,"inherited":5}`
	if err := jsonx.DecodeStrict(strings.NewReader(in), &got, lim); err != nil {
		t.Fatal(err)
	}
	if got.Lower.A != 7 || len(got.List) != 1 || got.List[0].K != 2 || got.Plain != 3 || got.Inherited != 5 {
		t.Fatalf("decoded %+v", got)
	}
	// The default stays strict.
	lim.AllowUnknownFields = false
	if err := jsonx.DecodeStrict(strings.NewReader(`{"zzz":1}`), &got, lim); !errors.Is(err, jsonx.ErrUnknownField) {
		t.Fatalf("default mode: %v", err)
	}
}
