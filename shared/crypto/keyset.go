package crypto

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
)

// MaxKeyPEMBytes is the largest PEM document ParseES256PrivateKeysPEM reads.
const MaxKeyPEMBytes = 64 << 10

// SigningKey is a private signing key. ID is the RFC 7638 JWK thumbprint
// (SHA-256, unpadded base64url) of its public key and is used as the JWS kid.
// It is safe to log (fmt and slog show ID and Alg only) and refuses JSON and
// text marshaling.
type SigningKey struct {
	ID      string
	Alg     Algorithm
	Private crypto.Signer
}

// KeySource supplies signing keys. The first key is the active one; the rest
// are kept only to verify tokens signed before a rotation.
type KeySource interface {
	SigningKeys(ctx context.Context) ([]SigningKey, error)
}

// Public returns the public half of k after checking that k is a valid ES256
// key whose ID is its thumbprint.
func (k SigningKey) Public() (PublicKey, error) {
	if k.Alg != ES256 {
		return PublicKey{}, ErrUnsupportedAlgorithm
	}
	if k.Private == nil {
		return PublicKey{}, fmt.Errorf("%w: no private key", ErrInvalidKey)
	}
	pub, err := p256Public(k.Private.Public())
	if err != nil {
		return PublicKey{}, err
	}
	id, err := thumbprint(pub)
	if err != nil {
		return PublicKey{}, err
	}
	if k.ID != id {
		return PublicKey{}, fmt.Errorf("%w: key ID is not the RFC 7638 thumbprint", ErrInvalidKey)
	}
	return PublicKey{id: id, alg: ES256, key: pub}, nil
}

// p256Public returns a copy of pub, which must be a P-256 ECDSA key whose
// point is on the curve. The copy never aliases the signer's own key.
func p256Public(pub crypto.PublicKey) (*ecdsa.PublicKey, error) {
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec == nil || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: not an ECDSA P-256 key", ErrInvalidKey)
	}
	point, err := ec.Bytes()
	if err != nil {
		return nil, fmt.Errorf("%w: invalid P-256 point", ErrInvalidKey)
	}
	cp, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid P-256 point", ErrInvalidKey)
	}
	return cp, nil
}

// thumbprint is the RFC 7638 SHA-256 JWK thumbprint, unpadded base64url.
func thumbprint(pub *ecdsa.PublicKey) (string, error) {
	sum, err := (&jose.JSONWebKey{Key: pub}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("%w: thumbprint", ErrInvalidKey)
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// newES256Key wraps a P-256 private key, deriving its ID.
func newES256Key(priv *ecdsa.PrivateKey) (SigningKey, error) {
	pub, err := p256Public(priv.Public())
	if err != nil {
		return SigningKey{}, err
	}
	id, err := thumbprint(pub)
	if err != nil {
		return SigningKey{}, err
	}
	return SigningKey{ID: id, Alg: ES256, Private: priv}, nil
}

// GenerateES256 returns a fresh P-256 signing key.
func GenerateES256() (SigningKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return SigningKey{}, fmt.Errorf("crypto: generating key: %w", err)
	}
	return newES256Key(priv)
}

// ParseES256PrivateKeysPEM parses one or more "PRIVATE KEY" PEM blocks
// (PKCS #8) holding ECDSA P-256 keys, in order. Anything else (another curve
// or key type, SEC 1 or encrypted blocks, PEM headers, data between or after
// the blocks other than whitespace, a repeated key, more than MaxKeyPEMBytes)
// is refused with ErrInvalidKey. Errors never contain key material.
func ParseES256PrivateKeysPEM(data []byte) ([]SigningKey, error) {
	if len(data) > MaxKeyPEMBytes {
		return nil, fmt.Errorf("%w: PEM larger than %d bytes", ErrInvalidKey, MaxKeyPEMBytes)
	}
	var keys []SigningKey
	seen := map[string]bool{}
	for rest := bytes.TrimSpace(data); len(rest) > 0; rest = bytes.TrimSpace(rest) {
		block, next, err := decodeOneBlock(rest)
		if err != nil {
			return nil, err
		}
		rest = next
		key, err := parsePKCS8Block(block)
		if err != nil {
			return nil, fmt.Errorf("%w: block %d: %w", ErrInvalidKey, len(keys)+1, err)
		}
		if seen[key.ID] {
			return nil, fmt.Errorf("%w: block %d repeats a key", ErrInvalidKey, len(keys)+1)
		}
		seen[key.ID] = true
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no PEM block", ErrInvalidKey)
	}
	return keys, nil
}

// decodeOneBlock decodes the PEM block at the start of data. pem.Decode
// silently skips text before a BEGIN line and malformed blocks; both are
// refused: the consumed text must start with, and hold, exactly one BEGIN.
func decodeOneBlock(data []byte) (*pem.Block, []byte, error) {
	begin := []byte("-----BEGIN ")
	if !bytes.HasPrefix(data, begin) {
		return nil, nil, fmt.Errorf("%w: data outside PEM blocks", ErrInvalidKey)
	}
	block, rest := pem.Decode(data)
	if block == nil || bytes.Count(data[:len(data)-len(rest)], begin) != 1 {
		return nil, nil, fmt.Errorf("%w: malformed PEM block", ErrInvalidKey)
	}
	return block, rest, nil
}

func parsePKCS8Block(block *pem.Block) (SigningKey, error) {
	if block.Type != "PRIVATE KEY" || len(block.Headers) != 0 {
		return SigningKey{}, fmt.Errorf("%w: want an unencrypted PKCS #8 block", ErrInvalidKey)
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return SigningKey{}, fmt.Errorf("%w: not PKCS #8", ErrInvalidKey)
	}
	ec, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		return SigningKey{}, fmt.Errorf("%w: not an ECDSA P-256 key", ErrInvalidKey)
	}
	return newES256Key(ec)
}

// KeySet signs with its active key and publishes all its public keys. It is
// safe for concurrent use.
type KeySet struct {
	active jose.Signer
	public []PublicKey
}

// NewKeySet loads the keys of src once. The first key signs; every key is
// published and verifies. Keys must be valid ES256 keys whose IDs are their
// thumbprints, with no ID repeated.
func NewKeySet(ctx context.Context, src KeySource) (*KeySet, error) {
	keys, err := src.SigningKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("crypto: loading signing keys: %w", err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no signing keys", ErrInvalidKey)
	}
	public := make([]PublicKey, 0, len(keys))
	for _, k := range keys {
		pub, err := k.Public()
		if err != nil {
			return nil, err
		}
		public = append(public, pub)
	}
	if err := checkUniqueIDs(public); err != nil {
		return nil, err
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       jose.JSONWebKey{Key: cryptosigner.Opaque(keys[0].Private), KeyID: keys[0].ID},
	}, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: signer", ErrInvalidKey)
	}
	return &KeySet{active: signer, public: public}, nil
}

func checkUniqueIDs(keys []PublicKey) error {
	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		if seen[k.id] {
			return fmt.Errorf("%w: repeated key ID", ErrInvalidKey)
		}
		seen[k.id] = true
	}
	return nil
}

// Sign returns claims, marshaled as JSON, as a compact JWS with the protected
// header {alg, kid, typ: "JWT"}. A token longer than MaxTokenBytes is refused,
// since no Verifier would accept it.
func (k *KeySet) Sign(claims any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", ErrInvalidClaims // json errors can quote claim content
	}
	jws, err := k.active.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("crypto: signing: %w", err)
	}
	token, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("crypto: serializing: %w", err)
	}
	if len(token) > MaxTokenBytes {
		return "", fmt.Errorf("%w: maximum %d bytes", ErrTokenTooLarge, MaxTokenBytes)
	}
	return token, nil
}

// PublicKeys returns the public keys of the set, active first.
func (k *KeySet) PublicKeys() []PublicKey {
	return append([]PublicKey(nil), k.public...)
}

// PublicJWKS returns the JWK Set (RFC 7517) of the public keys, active first,
// each with kty, crv, x, y, kid, alg and use. It never holds private material.
func (k *KeySet) PublicJWKS() ([]byte, error) {
	set := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(k.public))}
	for _, p := range k.public {
		jwk := jose.JSONWebKey{Key: p.key, KeyID: p.id, Algorithm: string(p.alg), Use: "sig"}
		if !jwk.IsPublic() {
			return nil, fmt.Errorf("%w: private key in public set", ErrInvalidKey)
		}
		set.Keys = append(set.Keys, jwk)
	}
	out, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshaling JWKS: %w", err)
	}
	return out, nil
}

// MarshalJSON always fails: a private key is never serialized by accident.
func (k SigningKey) MarshalJSON() ([]byte, error) { return nil, ErrKeyNotSerializable }

// MarshalText always fails: a private key is never serialized by accident.
func (k SigningKey) MarshalText() ([]byte, error) { return nil, ErrKeyNotSerializable }

// String shows the ID and algorithm only.
func (k SigningKey) String() string {
	return fmt.Sprintf("SigningKey{ID: %s, Alg: %s, Private: REDACTED}", k.ID, k.Alg)
}

// GoString keeps %#v from printing the private key.
func (k SigningKey) GoString() string { return k.String() }

// LogValue keeps slog from printing the private key.
func (k SigningKey) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", k.ID), slog.String("alg", string(k.Alg)))
}
