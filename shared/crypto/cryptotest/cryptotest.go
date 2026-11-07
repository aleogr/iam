// Package cryptotest builds key material for the tests of packages that may
// not import crypto/* themselves (depguard). It is for tests only: keys are
// generated fresh on every call and never written to the repository.
package cryptotest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// P256PEM returns a fresh ECDSA P-256 private key as a PKCS #8 PEM block.
func P256PEM(tb testing.TB) []byte {
	tb.Helper()
	return ecPEM(tb, elliptic.P256())
}

// P384PEM returns a fresh ECDSA P-384 private key as a PKCS #8 PEM block.
func P384PEM(tb testing.TB) []byte {
	tb.Helper()
	return ecPEM(tb, elliptic.P384())
}

// Ed25519PEM returns a fresh Ed25519 private key as a PKCS #8 PEM block.
func Ed25519PEM(tb testing.TB) []byte {
	tb.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return pkcs8PEM(tb, priv)
}

func ecPEM(tb testing.TB, c elliptic.Curve) []byte {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return pkcs8PEM(tb, priv)
}

func pkcs8PEM(tb testing.TB, priv any) []byte {
	tb.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		tb.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
