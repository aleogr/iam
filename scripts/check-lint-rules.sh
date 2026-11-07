#!/usr/bin/env bash
# Proves the architectural lint rules bite where they must and stay quiet where
# they must not: the fixture module must fail lint, every expected finding must
# be anchored to its fixture file, and the exempt files must have no finding.
# No `set -e`: the lint run is expected to exit non-zero and is handled explicitly.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Finding lines look like "<file>:<line>:<col>: ... (linter)". Depguard quotes
# the exact rule name ('name'), so a renamed rule such as core-no-infra-x fails.
# The fixture module is named github.com/aleogr/iam so that its imports carry
# the real paths the rules match (internal/..., shared/...).
expected=(
	"authn/core/violations\.go:[0-9]+:[0-9]+: .*'net/http' .*from list 'core-no-infra'"
	"authn/core/infra_import\.go:[0-9]+:[0-9]+: .*'github\.com/aleogr/iam/internal/database' .*from list 'core-no-infra'"
	"authn/core/violations\.go:[0-9]+:[0-9]+: .*time\.Now.*inject a clock"
	"authn/core/clock_alias\.go:[0-9]+:[0-9]+: .*t\.Since.*inject a clock"
	"internal/anywhere/violations\.go:[0-9]+:[0-9]+: .*from list 'crypto-only-in-shared-crypto'"
	"internal/anywhere/violations\.go:[0-9]+:[0-9]+: .*from list 'no-math-rand'"
	"examples/x/violation\.go:[0-9]+:[0-9]+: .*'github\.com/aleogr/iam/internal/database' .*from list 'examples-public-api-only'"
	"e2e/x/violation\.go:[0-9]+:[0-9]+: .*'github\.com/aleogr/iam/internal/database' .*from list 'examples-public-api-only'"
	"internal/testhelpers/violation\.go:[0-9]+:[0-9]+: .*'github\.com/aleogr/iam/shared/crypto/cryptotest' .*from list 'cryptotest-only-in-tests'"
)
absent=(
	"internal/anywhere/clock_ok\.go:[0-9]+:[0-9]+: .*inject a clock"
	"shared/crypto/sha\.go:[0-9]+:[0-9]+: .*crypto-only-in-shared-crypto"
	"authn/core/shared_ok\.go:[0-9]+:[0-9]+: "
	"internal/testhelpers/ok_test\.go:[0-9]+:[0-9]+: "
)

cd "$root/tools/lintfixture" || exit 1
out="$(GOWORK=off go tool -modfile="$root/tools/golangci-lint/go.mod" golangci-lint run --config "$root/.golangci.yml" ./... 2>&1)"
status=$?

if [ "$status" -eq 0 ]; then
	echo "FAIL: lint fixture passed; the boundary rules do not bite" >&2
	exit 1
fi

bad=0
for re in "${expected[@]}"; do
	if ! grep -qE -- "$re" <<<"$out"; then
		echo "FAIL: expected finding not found: $re" >&2
		bad=1
	fi
done
for re in "${absent[@]}"; do
	if grep -qE -- "$re" <<<"$out"; then
		echo "FAIL: unexpected finding present: $re" >&2
		bad=1
	fi
done
if [ "$bad" -ne 0 ]; then
	echo "$out" >&2
	exit 1
fi
echo "all ${#expected[@]} boundary rules fired; ${#absent[@]} exemptions held"
