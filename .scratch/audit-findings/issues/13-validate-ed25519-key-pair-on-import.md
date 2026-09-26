# 13: Validate imported Ed25519 private and public keys

**What to build:** An imported OpenSSH Ed25519 identity is accepted only when its private seed corresponds to its parsed public key.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Derive the Ed25519 public key from the imported private seed.
- [ ] Compare it with the public key serialized in the imported key.
- [ ] Reject mismatched key material before constructing an identity.
- [ ] Test a malformed key whose serialized public-key copies agree but do not match its private seed.
