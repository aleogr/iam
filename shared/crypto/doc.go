// Package crypto is the single cryptography entry point of the platform
// (contract C2): randomness, message authentication, constant-time comparison,
// password hashing, and ES256 JOSE signing and verification with JWKS
// publication (ADR 0010). No other package imports crypto/*,
// golang.org/x/crypto or go-jose.
//
// Errors never contain passwords, keys, tags, hashes or token content.
package crypto
