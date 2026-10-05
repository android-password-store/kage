#!/usr/bin/env bash
# Behavior-level interoperability tests for the age CLI and kage's CLI.
# Inspired by and translated from rage
# https://github.com/str4d/rage/blob/b5b68c4f4f7ea5c368bc060f6fe0237549c3a13f/.github/workflows/interop.yml
set -euo pipefail

AGE_BIN=${AGE_BIN:-age}
AGE_KEYGEN_BIN=${AGE_KEYGEN_BIN:-age-keygen}
KAGE_BIN=${KAGE_BIN:-"$(cd "$(dirname "$0")" && pwd)/build/install/age/bin/age"}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_plaintext() {
  local expected=$1
  local actual=$2
  cmp -s "$expected" "$actual" || fail "decrypted content differed: $actual"
}

# Check the same user-visible option surface before exercising file and stream
# behavior. Version strings intentionally aren't compared across implementations.
for cli in "$AGE_BIN" "$KAGE_BIN"; do
  "$cli" --version >"$tmp/version" || fail "$cli --version failed"
  test -s "$tmp/version" || fail "$cli --version printed no version"
  "$cli" --help >"$tmp/help" 2>&1 || fail "$cli --help failed"
  for option in --encrypt --decrypt --output --armor --passphrase --recipient --recipients-file --identity; do
    grep -q -- "$option" "$tmp/help" || fail "$cli --help omitted $option"
  done
done

# Empty invocation prints usage, while --help is a successful explicit request.
for cli in "$AGE_BIN" "$KAGE_BIN"; do
  set +e
  "$cli" >"$tmp/empty.stdout" 2>"$tmp/empty.stderr"
  set -e
  cat "$tmp/empty.stdout" "$tmp/empty.stderr" >"$tmp/empty.output"
  grep -q '^Usage:' "$tmp/empty.output" || fail "$cli with no arguments omitted usage"
done

# An invalid option must fail without writing encrypted data to stdout. The
# canonical CLI returns status 2 for unknown flags; the clone should match it.
for cli in "$AGE_BIN" "$KAGE_BIN"; do
  set +e
  "$cli" --not-an-age-option >"$tmp/unknown.stdout" 2>"$tmp/unknown.stderr"
  status=$?
  set -e
  test "$status" -eq 2 || fail "$cli unknown-option status was $status, expected 2"
  test ! -s "$tmp/unknown.stdout" || fail "$cli wrote stdout for an unknown option"
done

printf 'age CLI interop fixture\nsecond line\n' >"$tmp/plain"

make_keypair() {
  local kind=$1
  local identity="$tmp/$kind.identity"
  local recipient="$tmp/$kind.recipient"

  case "$kind" in
    x25519|pq)
      if [[ $kind == pq ]]; then
        "$AGE_KEYGEN_BIN" -pq -o "$identity" 2>/dev/null
      else
        "$AGE_KEYGEN_BIN" -o "$identity" 2>/dev/null
      fi
      awk '/^# public key: / { print $4 }' "$identity" >"$recipient"
      ;;
    ssh-rsa)
      ssh-keygen -q -t rsa -N '' -f "$identity"
      mv "$identity.pub" "$recipient"
      ;;
    ssh-ed25519)
      ssh-keygen -q -t ed25519 -N '' -f "$identity"
      mv "$identity.pub" "$recipient"
      ;;
    *) fail "unknown fixture key type: $kind" ;;
  esac
  test -s "$identity" && test -s "$recipient" || fail "failed to create $kind fixture"
}

round_trip() {
  local encryptor=$1
  local decryptor=$2
  local kind=$3
  local recipient="$tmp/$kind.recipient"
  local identity="$tmp/$kind.identity"
  local public_key
  public_key=$(cat "$recipient")
  local label="$kind-${encryptor##*/}-${decryptor##*/}"

  # Positional input, named output, and a direct recipient argument (including
  # SSH recipients, which age accepts through -r as well as recipients files).
  "$encryptor" -r "$public_key" -o "$tmp/$label.file.age" "$tmp/plain"
  "$decryptor" -d -i "$identity" -o "$tmp/$label.file.out" "$tmp/$label.file.age"
  assert_plaintext "$tmp/plain" "$tmp/$label.file.out"

  # ASCII armor, then CRLF line endings as commonly introduced by Windows tools.
  "$encryptor" -a -r "$public_key" -o "$tmp/$label.armor.age" "$tmp/plain"
  awk '{ printf "%s\r\n", $0 }' "$tmp/$label.armor.age" >"$tmp/$label.crlf.age"
  "$decryptor" -d -i "$identity" -o "$tmp/$label.armor.out" "$tmp/$label.crlf.age"
  assert_plaintext "$tmp/plain" "$tmp/$label.armor.out"

  # Implicit stdin/stdout via a pipeline.
  cat "$tmp/plain" |
    "$encryptor" -r "$public_key" |
    "$decryptor" -d -i "$identity" >"$tmp/$label.pipe.out"
  assert_plaintext "$tmp/plain" "$tmp/$label.pipe.out"

  # Explicit stdout during encryption and explicit stdin during decryption.
  "$encryptor" -a -r "$public_key" -o - "$tmp/plain" >"$tmp/$label.explicit.age"
  cat "$tmp/$label.explicit.age" |
    "$decryptor" -d -i "$identity" - >"$tmp/$label.explicit.out"
  assert_plaintext "$tmp/plain" "$tmp/$label.explicit.out"

  # Recipients can come from a file or stdin. Exercise repeated -R options and
  # comments/blank lines in recipient files.
  {
    printf '# generated recipient\n\n'
    cat "$recipient"
  } >"$tmp/$label.recipients"
  "$encryptor" -R "$tmp/$label.recipients" -o "$tmp/$label.recipient-file.age" "$tmp/plain"
  "$decryptor" -d -i "$identity" "$tmp/$label.recipient-file.age" >"$tmp/$label.recipient-file.out"
  assert_plaintext "$tmp/plain" "$tmp/$label.recipient-file.out"

  printf '%s\n' "$public_key" >"$tmp/$label.recipients.1"
  printf '%s\n' "$public_key" >"$tmp/$label.recipients.2"
  "$encryptor" -R "$tmp/$label.recipients.1" -R "$tmp/$label.recipients.2" \
    -o "$tmp/$label.repeated-recipient-files.age" "$tmp/plain"
  "$decryptor" -d -i "$identity" "$tmp/$label.repeated-recipient-files.age" \
    >"$tmp/$label.repeated-recipient-files.out"
  assert_plaintext "$tmp/plain" "$tmp/$label.repeated-recipient-files.out"

  cat "$recipient" |
    "$encryptor" -e -R - -o "$tmp/$label.recipient-stdin.age" "$tmp/plain"
  "$decryptor" -d -i "$identity" "$tmp/$label.recipient-stdin.age" >"$tmp/$label.recipient-stdin.out"
  assert_plaintext "$tmp/plain" "$tmp/$label.recipient-stdin.out"

  # Identity files may be supplied on stdin or through a process-substitution
  # path, in addition to ordinary paths.
  cat "$identity" |
    "$decryptor" -d -i - "$tmp/$label.file.age" >"$tmp/$label.identity-stdin.out"
  assert_plaintext "$tmp/plain" "$tmp/$label.identity-stdin.out"

  "$decryptor" -d -i <(cat "$identity") "$tmp/$label.file.age" >"$tmp/$label.identity-fd.out"
  assert_plaintext "$tmp/plain" "$tmp/$label.identity-fd.out"

  # The explicit -e/-i form encrypts to the public key derived from an identity.
  "$encryptor" -e -i "$identity" -o "$tmp/$label.identity.age" "$tmp/plain"
  "$decryptor" -d -i "$identity" "$tmp/$label.identity.age" >"$tmp/$label.identity.out"
  assert_plaintext "$tmp/plain" "$tmp/$label.identity.out"

  # Existing output files are overwritten, not appended to or rejected.
  printf 'stale output\n' >"$tmp/$label.overwrite.out"
  "$encryptor" -r "$public_key" -o "$tmp/$label.overwrite.age" "$tmp/plain"
  "$decryptor" -d -i "$identity" -o "$tmp/$label.overwrite.out" "$tmp/$label.overwrite.age"
  assert_plaintext "$tmp/plain" "$tmp/$label.overwrite.out"
}

# Like rage's alice -> bob matrix, test both directions with both CLI binaries.
# X25519, hybrid post-quantum, and SSH recipient forms are covered independently.
for kind in x25519 pq ssh-rsa ssh-ed25519; do
  make_keypair "$kind"
  for encryptor in "$AGE_BIN" "$KAGE_BIN"; do
    for decryptor in "$AGE_BIN" "$KAGE_BIN"; do
      round_trip "$encryptor" "$decryptor" "$kind"
    done
  done
done

# Invalid mode combinations and invalid inputs fail without leaking data to stdout.
expect_failure() {
  local cli=$1
  shift
  set +e
  "$cli" "$@" >"$tmp/failure.stdout" 2>"$tmp/failure.stderr"
  local status=$?
  set -e
  test "$status" -ne 0 || fail "$cli unexpectedly succeeded: $*"
  test ! -s "$tmp/failure.stdout" || fail "$cli wrote stdout on failure: $*"
}

for cli in "$AGE_BIN" "$KAGE_BIN"; do
  expect_failure "$cli" -e -d
  expect_failure "$cli" -e
  expect_failure "$cli" -e -r "$(cat "$tmp/x25519.recipient")" "$tmp/no-such-input"
  expect_failure "$cli" -d -i "$tmp/x25519.identity" "$tmp/plain"
done

# Repeated recipient options produce a file decryptable by either identity.
"$AGE_KEYGEN_BIN" -o "$tmp/second.identity" 2>/dev/null
second_recipient=$(awk '/^# public key: / { print $4 }' "$tmp/second.identity")
first_recipient=$(cat "$tmp/x25519.recipient")
for encryptor in "$AGE_BIN" "$KAGE_BIN"; do
  for decryptor in "$AGE_BIN" "$KAGE_BIN"; do
    "$encryptor" -r "$first_recipient" -r "$second_recipient" -o "$tmp/multiple.age" "$tmp/plain"
    "$decryptor" -d -i "$tmp/second.identity" "$tmp/multiple.age" >"$tmp/multiple.out"
    assert_plaintext "$tmp/plain" "$tmp/multiple.out"
    "$decryptor" -d -i "$tmp/second.identity" -i "$tmp/x25519.identity" "$tmp/multiple.age" >"$tmp/multiple-identities.out"
    assert_plaintext "$tmp/plain" "$tmp/multiple-identities.out"
  done
done

echo 'age CLI behavior and interoperability checks passed'
