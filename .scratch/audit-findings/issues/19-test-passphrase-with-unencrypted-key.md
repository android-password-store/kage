# 19: Test passphrase overload with unencrypted SSH keys

**What to build:** Callers can supply a passphrase uniformly while importing both encrypted and unencrypted SSH keys.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Use an existing unencrypted SSH key fixture with the passphrase-taking import overload.
- [ ] Verify the resulting identity is usable for the corresponding public key.
- [ ] Confirm the supplied passphrase is ignored for an unencrypted key.
