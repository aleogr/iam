package localfile_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aleogr/iam/adapters/keys/localfile"
	"github.com/aleogr/iam/shared/crypto"
	"github.com/aleogr/iam/shared/crypto/cryptotest"
)

func write(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys.pem")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLocalFile_LoadsKeysInOrder(t *testing.T) {
	active, previous := cryptotest.P256PEM(t), cryptotest.P256PEM(t)
	keys, err := localfile.New(write(t, append(active, previous...))).SigningKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want, err := crypto.ParseES256PrivateKeysPEM(active)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].ID != want[0].ID || keys[0].Alg != crypto.ES256 {
		t.Fatalf("keys = %+v", keys)
	}

	ks, err := crypto.NewKeySet(context.Background(), localfile.New(write(t, active)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Sign(map[string]string{"sub": "x"}); err != nil {
		t.Fatal(err)
	}
}

func TestLocalFile_RejectsNonP256(t *testing.T) {
	for name, data := range map[string][]byte{
		"P-384":             cryptotest.P384PEM(t),
		"Ed25519":           cryptotest.Ed25519PEM(t),
		"P-384 after P-256": append(cryptotest.P256PEM(t), cryptotest.P384PEM(t)...),
	} {
		_, err := localfile.New(write(t, data)).SigningKeys(context.Background())
		if !errors.Is(err, crypto.ErrInvalidKey) {
			t.Errorf("%s: err = %v, want ErrInvalidKey", name, err)
		}
	}
}

func TestLocalFile_RejectsOversizeFile(t *testing.T) {
	data := append(cryptotest.P256PEM(t), bytes.Repeat([]byte("\n"), crypto.MaxKeyPEMBytes)...)
	_, err := localfile.New(write(t, data)).SigningKeys(context.Background())
	if !errors.Is(err, crypto.ErrInvalidKey) {
		t.Fatalf("err = %v, want ErrInvalidKey", err)
	}
}

func TestLocalFile_MissingFileAndCancelledContext(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pem")
	if _, err := localfile.New(missing).SigningKeys(context.Background()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: err = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := localfile.New(write(t, cryptotest.P256PEM(t))).SigningKeys(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: err = %v", err)
	}
}
