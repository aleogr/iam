package testhelpers

import (
	"testing"

	"github.com/aleogr/iam/shared/crypto/cryptotest"
)

// Test files may import cryptotest; no rule must fire here.
func TestKey(t *testing.T) {
	if cryptotest.P256PEM() != nil {
		t.Fatal("fixture")
	}
}
