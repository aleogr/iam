// Package testhelpers is a lint fixture: production code must not import the test-only key helpers.
package testhelpers

import "github.com/aleogr/iam/shared/crypto/cryptotest"

// Key uses cryptotest outside a test file.
func Key() []byte { return cryptotest.P256PEM() }
