package crypto

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The EC key of RFC 7517 appendices A.1 and A.2.
const (
	rfc7517D = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
	// rfc7517Thumbprint is base64url(SHA-256(`{"crv":"P-256","kty":"EC","x":...,"y":...}`))
	// for that key, computed outside Go from the x and y of RFC 7517 A.1.
	rfc7517Thumbprint = "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s"
)

var b64u = base64.RawURLEncoding

type staticSource []SigningKey

func (s staticSource) SigningKeys(context.Context) ([]SigningKey, error) { return s, nil }

type errSource struct{ err error }

func (s errSource) SigningKeys(context.Context) ([]SigningKey, error) { return nil, s.err }

type testClaims struct {
	Sub string `json:"sub"`
	Aud string `json:"aud"`
}

func rfcPrivateKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	d, err := b64u.DecodeString(rfc7517D)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func pkcs8PEM(t testing.TB, priv any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func rfcSigningKey(t testing.TB) SigningKey {
	t.Helper()
	keys, err := ParseES256PrivateKeysPEM(pkcs8PEM(t, rfcPrivateKey(t)))
	if err != nil || len(keys) != 1 {
		t.Fatalf("ParseES256PrivateKeysPEM: %v, %d keys", err, len(keys))
	}
	return keys[0]
}

func newKey(t testing.TB) SigningKey {
	t.Helper()
	k, err := GenerateES256()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newKeySet(t testing.TB, keys ...SigningKey) *KeySet {
	t.Helper()
	ks, err := NewKeySet(context.Background(), staticSource(keys))
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func newVerifier(t testing.TB, ks *KeySet) *Verifier {
	t.Helper()
	v, err := NewVerifier(ks.PublicKeys(), []Algorithm{ES256})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// forge builds a compact JWS from raw header and payload JSON with the given
// signature function, bypassing KeySet so that hostile tokens can be made.
func forge(header, payload string, sign func(signingInput []byte) []byte) string {
	in := b64u.EncodeToString([]byte(header)) + "." + b64u.EncodeToString([]byte(payload))
	return in + "." + b64u.EncodeToString(sign([]byte(in)))
}

func es256(t testing.TB, priv *ecdsa.PrivateKey) func([]byte) []byte {
	return func(in []byte) []byte {
		h := sha256.Sum256(in)
		r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out
	}
}

func hs256(key []byte) func([]byte) []byte {
	return func(in []byte) []byte {
		m := hmac.New(sha256.New, key)
		m.Write(in)
		return m.Sum(nil)
	}
}

func segments(t testing.TB, token string) []string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments", len(parts))
	}
	return parts
}

func TestSignVerify_RoundTrip(t *testing.T) {
	key := newKey(t)
	ks := newKeySet(t, key)
	in := testClaims{Sub: "user-1", Aud: "client-a"}
	token, err := ks.Sign(in)
	if err != nil {
		t.Fatal(err)
	}

	var out testClaims
	if err := newVerifier(t, ks).Verify(token, &out); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out != in {
		t.Fatalf("claims = %+v, want %+v", out, in)
	}

	raw, err := b64u.DecodeString(segments(t, token)[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"alg": "ES256", "kid": key.ID, "typ": "JWT"}
	if len(header) != len(want) {
		t.Fatalf("header = %v, want %v", header, want)
	}
	for k, v := range want {
		if header[k] != v {
			t.Fatalf("header = %v, want %v", header, want)
		}
	}
}

func TestSignVerify_RotatedKeysStillVerify(t *testing.T) {
	oldKey, newKeyK := newKey(t), newKey(t)
	oldToken, err := newKeySet(t, oldKey).Sign(testClaims{Sub: "old"})
	if err != nil {
		t.Fatal(err)
	}
	// The new key is active; the old one is kept for verification only.
	ks := newKeySet(t, newKeyK, oldKey)
	token, err := ks.Sign(testClaims{Sub: "new"})
	if err != nil {
		t.Fatal(err)
	}
	if got := segments(t, token)[0]; !strings.Contains(string(mustB64(t, got)), newKeyK.ID) {
		t.Fatal("token not signed with the first (active) key")
	}
	v := newVerifier(t, ks)
	for _, tok := range []string{oldToken, token} {
		var c testClaims
		if err := v.Verify(tok, &c); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}
}

func mustB64(t testing.TB, s string) []byte {
	t.Helper()
	b, err := b64u.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerify_RejectsAlgNone(t *testing.T) {
	key := newKey(t)
	v := newVerifier(t, newKeySet(t, key))
	payload := `{"sub":"admin","aud":"client-a"}`
	for _, alg := range []string{"none", "None", "NONE", "nOnE", ""} {
		header := `{"alg":"` + alg + `","kid":"` + key.ID + `","typ":"JWT"}`
		for _, sig := range []func([]byte) []byte{
			func([]byte) []byte { return nil },
			es256(t, key.Private.(*ecdsa.PrivateKey)),
		} {
			var c testClaims
			err := v.Verify(forge(header, payload, sig), &c)
			if !errors.Is(err, ErrUnsupportedAlgorithm) {
				t.Errorf("alg %q: err = %v, want ErrUnsupportedAlgorithm", alg, err)
			}
			if c != (testClaims{}) {
				t.Errorf("alg %q: claims written on failure: %+v", alg, c)
			}
		}
	}
}

// Algorithm confusion (TM-OIDC-001): an attacker signs with HMAC using the
// public key, in every form it is published, as the shared secret.
func TestVerify_RejectsHS256WithPublicKeyAsSecret(t *testing.T) {
	key := newKey(t)
	ks := newKeySet(t, key)
	v := newVerifier(t, ks)
	pub := key.Private.Public().(*ecdsa.PublicKey)
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	point, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := ks.PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string][]byte{
		"point": point,
		"spki":  spki,
		"pem":   pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}),
		"jwks":  jwks,
	}
	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		for name, secret := range secrets {
			header := `{"alg":"` + alg + `","kid":"` + key.ID + `","typ":"JWT"}`
			var c testClaims
			err := v.Verify(forge(header, `{"sub":"admin"}`, hs256(secret)), &c)
			if !errors.Is(err, ErrUnsupportedAlgorithm) {
				t.Errorf("%s with %s: err = %v, want ErrUnsupportedAlgorithm", alg, name, err)
			}
		}
	}
	// Another asymmetric algorithm with the right kid is refused too.
	for _, alg := range []string{"ES384", "ES512", "RS256", "PS256", "EdDSA"} {
		header := `{"alg":"` + alg + `","kid":"` + key.ID + `"}`
		err := v.Verify(forge(header, `{"sub":"admin"}`, es256(t, key.Private.(*ecdsa.PrivateKey))), new(testClaims))
		if !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("%s: err = %v, want ErrUnsupportedAlgorithm", alg, err)
		}
	}
}

func TestVerify_RejectsUnknownKid(t *testing.T) {
	trusted, other := newKey(t), newKey(t)
	v := newVerifier(t, newKeySet(t, trusted))
	token, err := newKeySet(t, other).Sign(testClaims{Sub: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(token, new(testClaims)); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("other key: err = %v, want ErrUnknownKey", err)
	}
	priv := trusted.Private.(*ecdsa.PrivateKey)
	for name, header := range map[string]string{
		"missing kid": `{"alg":"ES256"}`,
		"empty kid":   `{"alg":"ES256","kid":""}`,
		"case":        `{"alg":"ES256","kid":"` + strings.ToUpper(trusted.ID) + `"}`,
	} {
		if err := v.Verify(forge(header, `{"sub":"x"}`, es256(t, priv)), new(testClaims)); !errors.Is(err, ErrUnknownKey) {
			t.Errorf("%s: err = %v, want ErrUnknownKey", name, err)
		}
	}
}

func TestVerify_RejectsOversizeToken(t *testing.T) {
	key := newKey(t)
	ks := newKeySet(t, key)
	v := newVerifier(t, ks)

	// Size is checked before parsing: garbage one byte over the limit is
	// refused as too large, the same garbage at the limit as malformed.
	if err := v.Verify(strings.Repeat("a", MaxTokenBytes+1), new(testClaims)); !errors.Is(err, ErrTokenTooLarge) {
		t.Fatalf("8 KiB + 1: err = %v, want ErrTokenTooLarge", err)
	}
	if err := v.Verify(strings.Repeat("a", MaxTokenBytes), new(testClaims)); !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("8 KiB: err = %v, want ErrMalformedToken", err)
	}

	// A validly signed token over the limit is refused too.
	big := forge(`{"alg":"ES256","kid":"`+key.ID+`"}`, `{"sub":"`+strings.Repeat("x", MaxTokenBytes)+`"}`,
		es256(t, key.Private.(*ecdsa.PrivateKey)))
	if err := v.Verify(big, new(testClaims)); !errors.Is(err, ErrTokenTooLarge) {
		t.Fatalf("signed oversize: err = %v, want ErrTokenTooLarge", err)
	}

	// Sign never produces a token that Verify would refuse.
	if _, err := ks.Sign(testClaims{Sub: strings.Repeat("x", MaxTokenBytes)}); !errors.Is(err, ErrTokenTooLarge) {
		t.Fatalf("Sign oversize: err = %v, want ErrTokenTooLarge", err)
	}
}

func TestVerify_RejectsTamperedPayload(t *testing.T) {
	key := newKey(t)
	ks := newKeySet(t, key)
	v := newVerifier(t, ks)
	token, err := ks.Sign(testClaims{Sub: "user-1", Aud: "client-a"})
	if err != nil {
		t.Fatal(err)
	}
	p := segments(t, token)
	evil := b64u.EncodeToString([]byte(`{"sub":"admin","aud":"client-a"}`))
	sig := mustB64(t, p[2])
	flipped := append([]byte(nil), sig...)
	flipped[10] ^= 0x01
	cases := map[string]string{
		"payload swapped":   p[0] + "." + evil + "." + p[2],
		"signature flipped": p[0] + "." + p[1] + "." + b64u.EncodeToString(flipped),
		"signature empty":   p[0] + "." + p[1] + ".",
		"signature short":   p[0] + "." + p[1] + "." + b64u.EncodeToString(sig[:63]),
		"header swapped":    b64u.EncodeToString([]byte(`{"kid":"`+key.ID+`","alg":"ES256","typ":"JWT"}`)) + "." + p[1] + "." + p[2],
	}
	for name, tok := range cases {
		var c testClaims
		if err := v.Verify(tok, &c); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("%s: err = %v, want ErrInvalidSignature", name, err)
		}
		if c != (testClaims{}) {
			t.Errorf("%s: claims written on failure", name)
		}
	}
}

// Encodings that decode to the same bytes are still a different token: only
// canonical unpadded base64url without whitespace is accepted.
func TestVerify_RejectsNonCanonicalEncoding(t *testing.T) {
	ks := newKeySet(t, newKey(t))
	v := newVerifier(t, ks)
	token, err := ks.Sign(testClaims{Sub: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	p := segments(t, token)
	// 64 signature bytes take 86 characters; the last one carries 2 unused bits.
	last := p[2][len(p[2])-1]
	idx := strings.IndexByte(b64urlAlphabet, last)
	sloppy := p[2][:len(p[2])-1] + string(b64urlAlphabet[idx|1])
	if idx|1 == idx {
		sloppy = p[2][:len(p[2])-1] + string(b64urlAlphabet[idx&^1])
	}
	cases := map[string]string{
		"padding bits": p[0] + "." + p[1] + "." + sloppy,
		"newline":      p[0] + "." + p[1][:4] + "\n" + p[1][4:] + "." + p[2],
		"carriage":     p[0] + "\r." + p[1] + "." + p[2],
		"padded":       p[0] + "." + p[1] + "." + p[2] + "==",
		"leading ws":   " " + token,
		"trailing ws":  token + "\n",
		"std alphabet": strings.NewReplacer("-", "+", "_", "/").Replace(token),
		"json form":    `{"payload":"` + p[1] + `","protected":"` + p[0] + `","signature":"` + p[2] + `"}`,
		"four parts":   token + ".",
	}
	for name, tok := range cases {
		if tok == token {
			continue // the replacement found nothing to change
		}
		if err := v.Verify(tok, new(testClaims)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TM-OIDC-001/008: keys named or embedded in the header are never used. An
// attacker who embeds their own key and signs with it, while naming a trusted
// kid, is refused.
func TestVerify_RejectsEmbeddedJWK(t *testing.T) {
	trusted := newKey(t)
	v := newVerifier(t, newKeySet(t, trusted))
	attacker := newKey(t)
	jwks, err := newKeySet(t, attacker).PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	var set struct{ Keys []json.RawMessage }
	if err := json.Unmarshal(jwks, &set); err != nil {
		t.Fatal(err)
	}
	attackerPriv := attacker.Private.(*ecdsa.PrivateKey)
	for _, kid := range []string{trusted.ID, attacker.ID} {
		header := `{"alg":"ES256","kid":"` + kid + `","jwk":` + string(set.Keys[0]) + `}`
		var c testClaims
		err := v.Verify(forge(header, `{"sub":"admin"}`, es256(t, attackerPriv)), &c)
		if !errors.Is(err, ErrMalformedToken) {
			t.Fatalf("kid %s: err = %v, want ErrMalformedToken", kid, err)
		}
		if c != (testClaims{}) {
			t.Fatalf("kid %s: claims written", kid)
		}
	}
}

// Header members other than alg, kid and typ are refused even when the token
// is signed by a trusted key: jku, jwk, x5u, x5c, crit and b64 included.
func TestVerify_RejectsUntrustedHeaderParameters(t *testing.T) {
	key := newKey(t)
	v := newVerifier(t, newKeySet(t, key))
	priv := key.Private.(*ecdsa.PrivateKey)
	base := `"alg":"ES256","kid":"` + key.ID + `"`
	for name, extra := range map[string]string{
		"jku":       `"jku":"https://attacker.invalid/jwks"`,
		"x5u":       `"x5u":"https://attacker.invalid/cert"`,
		"x5c":       `"x5c":["MIIB"]`,
		"jwk":       `"jwk":{"kty":"EC"}`,
		"crit":      `"crit":["b64"],"b64":true`,
		"b64":       `"b64":false`,
		"duplicate": `"alg":"ES256"`,
		"case":      `"ALG":"none"`,
		"cty":       `"cty":"JWT"`,
	} {
		header := `{` + base + `,` + extra + `}`
		if err := v.Verify(forge(header, `{"sub":"x"}`, es256(t, priv)), new(testClaims)); !errors.Is(err, ErrMalformedToken) {
			t.Errorf("%s: err = %v, want ErrMalformedToken", name, err)
		}
	}
}

func TestVerify_ClaimsDecodedStrictly(t *testing.T) {
	key := newKey(t)
	v := newVerifier(t, newKeySet(t, key))
	priv := key.Private.(*ecdsa.PrivateKey)
	header := `{"alg":"ES256","kid":"` + key.ID + `"}`
	for name, payload := range map[string]string{
		"duplicate":         `{"sub":"a","sub":"admin"}`,
		"case duplicate":    `{"sub":"a","SUB":"admin"}`,
		"case only":         `{"SUB":"admin"}`,
		"unknown duplicate": `{"sub":"a","role":1,"role":2}`,
		"trailing":          `{"sub":"a"}{}`,
		"not json":          `sub=a`,
	} {
		if err := v.Verify(forge(header, payload, es256(t, priv)), new(testClaims)); !errors.Is(err, ErrMalformedToken) {
			t.Errorf("%s: err = %v, want ErrMalformedToken", name, err)
		}
	}
}

// RFC 7519 section 4: claims that are not understood are ignored, so an
// issuer may add claims without breaking verifiers.
func TestVerify_IgnoresUnknownClaims(t *testing.T) {
	key := newKey(t)
	v := newVerifier(t, newKeySet(t, key))
	header := `{"alg":"ES256","kid":"` + key.ID + `"}`
	payload := `{"sub":"a","aud":"b","new_claim":{"x":[1,2]},"scope":"openid"}`
	var c testClaims
	if err := v.Verify(forge(header, payload, es256(t, key.Private.(*ecdsa.PrivateKey))), &c); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c != (testClaims{Sub: "a", Aud: "b"}) {
		t.Fatalf("claims = %+v", c)
	}
}

func TestVerify_RejectsInvalidDestination(t *testing.T) {
	ks := newKeySet(t, newKey(t))
	v := newVerifier(t, ks)
	token, err := ks.Sign(testClaims{Sub: "a"})
	if err != nil {
		t.Fatal(err)
	}
	var nilPtr *testClaims
	for name, dst := range map[string]any{"nil": nil, "value": testClaims{}, "nil pointer": nilPtr} {
		if err := v.Verify(token, dst); !errors.Is(err, ErrInvalidDestination) {
			t.Errorf("%s: err = %v, want ErrInvalidDestination", name, err)
		}
	}
}

func TestVerify_ErrorsHaveNoTokenContent(t *testing.T) {
	key := newKey(t)
	v := newVerifier(t, newKeySet(t, key))
	priv := key.Private.(*ecdsa.PrivateKey)
	const marker = "SECRETMARKER"
	tokens := []string{
		forge(`{"alg":"`+marker+`","kid":"`+marker+`"}`, `{"sub":"`+marker+`"}`, es256(t, priv)),
		forge(`{"alg":"ES256","kid":"`+marker+`"}`, `{"sub":"`+marker+`"}`, es256(t, priv)),
		forge(`{"alg":"ES256","kid":"`+key.ID+`","`+marker+`":1}`, `{}`, es256(t, priv)),
		forge(`{"alg":"ES256","kid":"`+key.ID+`"}`, `{"`+marker+`":1,"`+marker+`":2}`, es256(t, priv)),
		marker + "." + marker + "." + marker,
	}
	for _, tok := range tokens {
		err := v.Verify(tok, new(testClaims))
		if err == nil {
			t.Fatal("accepted")
		}
		if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), tok) {
			t.Errorf("error leaks token content: %v", err)
		}
	}
}

func TestNewVerifier_RejectsUnsupportedAlgorithms(t *testing.T) {
	pub := newKeySet(t, newKey(t)).PublicKeys()
	for _, allowed := range [][]Algorithm{nil, {}, {"none"}, {"HS256"}, {ES256, "HS256"}, {"es256"}} {
		if _, err := NewVerifier(pub, allowed); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("allowed %v: err = %v, want ErrUnsupportedAlgorithm", allowed, err)
		}
	}
	if _, err := NewVerifier(nil, []Algorithm{ES256}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("no keys: err = %v, want ErrInvalidKey", err)
	}
	dup := append(append([]PublicKey(nil), pub...), pub...)
	if _, err := NewVerifier(dup, []Algorithm{ES256}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("duplicate kid: err = %v, want ErrInvalidKey", err)
	}
	if _, err := NewVerifier([]PublicKey{{}}, []Algorithm{ES256}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("zero key: err = %v, want ErrInvalidKey", err)
	}
}

func TestPublicJWKS_HasNoPrivateMaterial(t *testing.T) {
	keys := []SigningKey{newKey(t), newKey(t)}
	jwks, err := newKeySet(t, keys...).PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != len(keys) {
		t.Fatalf("%d keys, want %d", len(set.Keys), len(keys))
	}
	for i, k := range set.Keys {
		checkPublicJWK(t, k, keys[i].ID)
		d, err := keys[i].Private.(*ecdsa.PrivateKey).Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(jwks), b64u.EncodeToString(d)) {
			t.Fatalf("JWKS contains the private scalar of key %d", i)
		}
	}
}

// checkPublicJWK asserts that jwk has exactly the public EC members.
func checkPublicJWK(t *testing.T, jwk map[string]any, kid string) {
	t.Helper()
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "k", "oth"} {
		if _, ok := jwk[private]; ok {
			t.Errorf("key %s has private member %q", kid, private)
		}
	}
	want := map[string]any{"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid}
	for name, v := range want {
		if jwk[name] != v {
			t.Errorf("key %s: %s = %v, want %v", kid, name, jwk[name], v)
		}
	}
	_, hasX := jwk["x"]
	_, hasY := jwk["y"]
	if !hasX || !hasY || len(jwk) != len(want)+2 {
		t.Errorf("key %s members: %v", kid, jwk)
	}
}

func TestKid_IsRFC7638Thumbprint(t *testing.T) {
	key := rfcSigningKey(t)
	if key.ID != rfc7517Thumbprint {
		t.Fatalf("kid = %s, want %s", key.ID, rfc7517Thumbprint)
	}
	if key.Alg != ES256 {
		t.Fatalf("alg = %s", key.Alg)
	}
	pub, err := key.Public()
	if err != nil || pub.ID() != rfc7517Thumbprint || pub.Alg() != ES256 {
		t.Fatalf("Public() = %+v, %v", pub, err)
	}
	gen := newKey(t)
	if want := thumbprintOf(t, gen.Private.Public().(*ecdsa.PublicKey)); gen.ID != want {
		t.Fatalf("generated kid = %s, want %s", gen.ID, want)
	}
}

// thumbprintOf is RFC 7638 written out by hand, independent of go-jose.
func thumbprintOf(t testing.TB, pub *ecdsa.PublicKey) string {
	t.Helper()
	point, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	canonical := `{"crv":"P-256","kty":"EC","x":"` + b64u.EncodeToString(point[1:33]) +
		`","y":"` + b64u.EncodeToString(point[33:]) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return b64u.EncodeToString(sum[:])
}

func TestNewKeySet_RejectsInvalidKeys(t *testing.T) {
	good := newKey(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]SigningKey{
		"empty":         nil,
		"wrong kid":     {{ID: "not-the-thumbprint", Alg: ES256, Private: good.Private}},
		"empty kid":     {{Alg: ES256, Private: good.Private}},
		"nil signer":    {{ID: good.ID, Alg: ES256}},
		"P-384":         {{ID: good.ID, Alg: ES256, Private: p384}},
		"Ed25519":       {{ID: good.ID, Alg: ES256, Private: edPriv}},
		"duplicate kid": {good, good},
	}
	for name, keys := range cases {
		if _, err := NewKeySet(context.Background(), staticSource(keys)); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: err = %v, want ErrInvalidKey", name, err)
		}
	}
	hs := good
	hs.Alg = "HS256"
	if _, err := NewKeySet(context.Background(), staticSource{hs}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("HS256: err = %v, want ErrUnsupportedAlgorithm", err)
	}
	boom := errors.New("boom")
	if _, err := NewKeySet(context.Background(), errSource{boom}); !errors.Is(err, boom) {
		t.Errorf("source error: err = %v", err)
	}
}

func TestParseES256PrivateKeysPEM(t *testing.T) {
	k1, k2 := rfcPrivateKey(t), newKey(t).Private
	keys, err := ParseES256PrivateKeysPEM(append(pkcs8PEM(t, k1), pkcs8PEM(t, k2)...))
	if err != nil || len(keys) != 2 || keys[0].ID != rfc7517Thumbprint {
		t.Fatalf("keys = %v, err = %v", keys, err)
	}
	// Whitespace around the blocks is fine.
	if _, err := ParseES256PrivateKeysPEM(append(append([]byte("\n"), pkcs8PEM(t, k1)...), "\n\n"...)); err != nil {
		t.Fatalf("surrounding newlines: %v", err)
	}
}

func TestParseES256PrivateKeysPEM_Rejects(t *testing.T) {
	k1 := rfcPrivateKey(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(k1)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":         nil,
		"no PEM":        []byte("not a key"),
		"P-384":         pkcs8PEM(t, p384),
		"Ed25519":       pkcs8PEM(t, edPriv),
		"SEC 1 block":   pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}),
		"wrong type":    pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: mustDER(t, k1)}),
		"headers":       pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: mustDER(t, k1)}),
		"leading junk":  append([]byte("junk\n"), pkcs8PEM(t, k1)...),
		"trailing junk": append(pkcs8PEM(t, k1), []byte("junk")...),
		"P-384 second":  append(pkcs8PEM(t, k1), pkcs8PEM(t, p384)...),
		"duplicate":     append(pkcs8PEM(t, k1), pkcs8PEM(t, k1)...),
		"oversize":      append(pkcs8PEM(t, k1), make([]byte, MaxKeyPEMBytes)...),
		"bad DER":       pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x30, 0x01}}),
		"skipped block": append([]byte("-----BEGIN JUNK-----\nnot base64 !!\n"), pkcs8PEM(t, k1)...),
		"unclosed key":  append([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n"), pkcs8PEM(t, k1)...),
		"skipped later": append(append(pkcs8PEM(t, k1), "-----BEGIN X-----\n"...), pkcs8PEM(t, newKey(t).Private)...),
	}
	for name, data := range cases {
		_, err := ParseES256PrivateKeysPEM(data)
		if !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: err = %v, want ErrInvalidKey", name, err)
		} else if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "junk") {
			t.Errorf("%s: error echoes input: %v", name, err)
		}
	}
}

func mustDER(t testing.TB, priv any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// fuzzToken was signed once by the RFC 7517 key with claims {"sub":"fuzz"};
// it is the only input FuzzVerify may see accepted. It is assembled from its
// parts so that secret scanners do not mistake a test vector for a credential.
var fuzzToken = b64u.EncodeToString([]byte(`{"alg":"ES256","kid":"`+rfc7517Thumbprint+`","typ":"JWT"}`)) + "." +
	b64u.EncodeToString([]byte(`{"sub":"fuzz"}`)) + "." +
	"h1K6yYuYV1f4Y1s_TZuhDS6LB_rMKUt6ppyDggl6zPvqIy7a0Ly6Sd08gV_37SfdsRnB8cuPMPZwUszAXixeJw"

func FuzzVerify(f *testing.F) {
	ks := newKeySet(f, rfcSigningKey(f))
	v := newVerifier(f, ks)
	p := strings.Split(fuzzToken, ".")
	f.Add(fuzzToken)
	f.Add(fuzzToken + ".")
	f.Add(p[0] + "." + p[1] + ".")
	f.Add(p[0] + ".." + p[2])
	f.Add(`{"payload":"` + p[1] + `","protected":"` + p[0] + `","signature":"` + p[2] + `"}`)
	f.Add(forge(`{"alg":"none","kid":"`+rfc7517Thumbprint+`"}`, `{"sub":"fuzz"}`, func([]byte) []byte { return nil }))
	f.Add(forge(`{"alg":"HS256","kid":"`+rfc7517Thumbprint+`"}`, `{"sub":"fuzz"}`, hs256([]byte("k"))))
	f.Add("")
	f.Add("...")
	sentinels := []error{ErrTokenTooLarge, ErrMalformedToken, ErrUnsupportedAlgorithm, ErrUnknownKey, ErrInvalidSignature}
	f.Fuzz(func(t *testing.T, tok string) {
		var dst map[string]any
		err := v.Verify(tok, &dst)
		if err == nil {
			if tok != fuzzToken && tok != fuzzTokenTwin {
				t.Fatalf("mutated token accepted: %q", tok)
			}
			return
		}
		if dst != nil {
			t.Fatal("claims written on failure")
		}
		for _, s := range sentinels {
			if errors.Is(err, s) {
				return
			}
		}
		t.Fatalf("error is not a sentinel: %v", err)
	})
}

// fuzzTokenTwin is fuzzToken with s replaced by n - s: ECDSA malleability
// makes it verify too, which is why tokens are identified by jti, never by
// their bytes.
var fuzzTokenTwin = highSTwin(fuzzToken)

func highSTwin(token string) string {
	p := strings.Split(token, ".")
	sig, err := b64u.DecodeString(p[2])
	if err != nil || len(sig) != 64 {
		panic("bad fixture")
	}
	s := new(big.Int).SetBytes(sig[32:])
	s.Sub(elliptic.P256().Params().N, s)
	twin := make([]byte, 64)
	copy(twin, sig[:32])
	s.FillBytes(twin[32:])
	return p[0] + "." + p[1] + "." + b64u.EncodeToString(twin)
}

func TestFuzzToken_HighSTwinVerifies(t *testing.T) {
	if fuzzTokenTwin == fuzzToken {
		t.Fatal("twin equals the token")
	}
	v := newVerifier(t, newKeySet(t, rfcSigningKey(t)))
	if err := v.Verify(fuzzTokenTwin, new(map[string]any)); err != nil {
		t.Fatalf("high-S twin: %v", err)
	}
}

// Keeps fuzzToken honest: it must verify, or FuzzVerify proves nothing.
func TestFuzzToken_IsValid(t *testing.T) {
	v := newVerifier(t, newKeySet(t, rfcSigningKey(t)))
	var c map[string]any
	if err := v.Verify(fuzzToken, &c); err != nil || c["sub"] != "fuzz" {
		t.Fatalf("fuzzToken: %v, %v", c, err)
	}
}

// A P-256 key (d = 43) whose y coordinate starts with a zero byte: x and y
// must stay 32 bytes (43 base64url characters) in the thumbprint and the
// JWKS. Expected values computed outside Go.
func TestKid_LeadingZeroCoordinate(t *testing.T) {
	const (
		wantX   = "mGriUG8f8QTQQjCGHY9LSY9LxMbQCbMPdUTcEpuC0o0"
		wantY   = "ADzMwKZGDgrjKKTZfTx7YdhvxiicGJ8lJREMRBuwfpc"
		wantKid = "WZsjbh58q8kl1WsGShqtiycImZtCgGbukDn4RAacMig"
	)
	d := make([]byte, 32)
	d[31] = 43
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseES256PrivateKeysPEM(pkcs8PEM(t, priv))
	if err != nil {
		t.Fatal(err)
	}
	if keys[0].ID != wantKid {
		t.Fatalf("kid = %s, want %s", keys[0].ID, wantKid)
	}
	jwks, err := newKeySet(t, keys[0]).PublicJWKS()
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []struct{ X, Y string } `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		t.Fatal(err)
	}
	if set.Keys[0].X != wantX || set.Keys[0].Y != wantY {
		t.Fatalf("x, y = %s, %s", set.Keys[0].X, set.Keys[0].Y)
	}
}

func TestKeySet_ConcurrentSignVerify(t *testing.T) {
	ks := newKeySet(t, newKey(t), newKey(t))
	v := newVerifier(t, ks)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for g := range 16 {
		wg.Go(func() {
			for i := range 20 {
				in := testClaims{Sub: strconv.Itoa(g), Aud: strconv.Itoa(i)}
				tok, err := ks.Sign(in)
				if err != nil {
					errs <- err
					return
				}
				var out testClaims
				if err := v.Verify(tok, &out); err != nil || out != in {
					errs <- fmt.Errorf("verify %+v: %v", out, err)
					return
				}
				_, _ = ks.PublicJWKS()
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

type failingClaims struct{}

func (failingClaims) MarshalJSON() ([]byte, error) {
	return nil, errors.New("SECRETMARKER in claims")
}

func TestSign_ErrorHasNoClaimContent(t *testing.T) {
	ks := newKeySet(t, newKey(t))
	for name, claims := range map[string]any{"marshaler": failingClaims{}, "func": map[string]any{"SECRETMARKER": func() {}}} {
		_, err := ks.Sign(claims)
		if !errors.Is(err, ErrInvalidClaims) {
			t.Errorf("%s: err = %v, want ErrInvalidClaims", name, err)
		} else if strings.Contains(err.Error(), "SECRETMARKER") {
			t.Errorf("%s: error leaks claims: %v", name, err)
		}
	}
}

func TestPublicKey_DoesNotAliasPrivateKey(t *testing.T) {
	key := newKey(t)
	pub, err := key.Public()
	if err != nil {
		t.Fatal(err)
	}
	priv := key.Private.(*ecdsa.PrivateKey)
	if pub.key == &priv.PublicKey || !pub.key.Equal(&priv.PublicKey) {
		t.Fatal("public key aliases the private key's or differs from it")
	}
	for _, p := range newKeySet(t, key).PublicKeys() {
		if p.key == &priv.PublicKey {
			t.Fatal("KeySet public key aliases the private key's")
		}
	}
}

// A SigningKey must be safe to log and impossible to serialize by accident.
func TestSigningKey_NeverExposesPrivateKey(t *testing.T) {
	key := rfcSigningKey(t)
	if _, err := json.Marshal(key); !errors.Is(err, ErrKeyNotSerializable) {
		t.Errorf("json.Marshal(key): err = %v", err)
	}
	if _, err := json.Marshal(struct{ K SigningKey }{key}); err == nil {
		t.Error("json.Marshal of a struct holding a key succeeded")
	}
	if _, err := json.Marshal(&key); err == nil {
		t.Error("json.Marshal(&key) succeeded")
	}
	if _, err := key.MarshalText(); !errors.Is(err, ErrKeyNotSerializable) {
		t.Errorf("MarshalText: err = %v", err)
	}
}

func TestSigningKey_RedactsWhenFormattedOrLogged(t *testing.T) {
	key := rfcSigningKey(t)
	dec := new(big.Int).SetBytes(mustB64(t, rfc7517D)).String()
	leaks := func(s string) bool { return strings.Contains(s, rfc7517D) || strings.Contains(s, dec) }
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		for _, arg := range []any{key, &key, []SigningKey{key}} {
			out := fmt.Sprintf(verb, arg)
			if leaks(out) || !strings.Contains(out, "REDACTED") || !strings.Contains(out, key.ID) {
				t.Errorf("%s of %T: %s", verb, arg, out)
			}
		}
	}
	if s := key.String(); s != key.GoString() || !strings.Contains(s, "ES256") || !strings.Contains(s, "REDACTED") {
		t.Errorf("String/GoString = %q / %q", s, key.GoString())
	}
}

func TestSigningKey_LogValueRedacts(t *testing.T) {
	key := rfcSigningKey(t)
	dec := new(big.Int).SetBytes(mustB64(t, rfc7517D)).String()
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("loaded", "key", key)
	slog.New(slog.NewTextHandler(&buf, nil)).Info("loaded", "key", key)
	if out := buf.String(); strings.Contains(out, rfc7517D) || strings.Contains(out, dec) || strings.Count(out, key.ID) != 2 {
		t.Errorf("slog output: %s", buf.String())
	}
}
