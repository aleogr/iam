// Package localfile is a KeySource (contract C2) that reads ES256 signing keys
// from a local file of PEM PKCS #8 P-256 keys, the active key first. It is for
// development and tests only; the lab source arrives in milestone 1D.
//
// Parsing and validation are done by shared/crypto; this package only reads
// the file.
package localfile

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/aleogr/iam/shared/crypto"
)

type source struct{ path string }

// New returns a KeySource that reads path on every call to SigningKeys.
func New(path string) crypto.KeySource { return source{path: path} }

// SigningKeys reads and parses the file. A file over crypto.MaxKeyPEMBytes is
// refused without reading the rest. Errors name the path, never key material.
func (s source) SigningKeys(ctx context.Context) ([]crypto.SigningKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(s.path) //nolint:gosec // the path comes from operator configuration, not from requests
	if err != nil {
		return nil, fmt.Errorf("localfile: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only file; a close error loses nothing
	data, err := io.ReadAll(io.LimitReader(f, crypto.MaxKeyPEMBytes+1))
	if err != nil {
		return nil, fmt.Errorf("localfile: reading %s: %w", s.path, err)
	}
	keys, err := crypto.ParseES256PrivateKeysPEM(data)
	if err != nil {
		return nil, fmt.Errorf("localfile: %s: %w", s.path, err)
	}
	return keys, nil
}
