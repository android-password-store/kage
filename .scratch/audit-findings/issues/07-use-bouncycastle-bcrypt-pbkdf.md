# 07: Replace duplicate bcrypt PBKDF with Bouncy Castle

**What to build:** SSH private-key import uses the existing Bouncy Castle bcrypt PBKDF implementation instead of maintaining a duplicate cryptographic implementation.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Use Bouncy Castle's bcrypt PBKDF API for OpenSSH key derivation while retaining required argument validation.
- [ ] Remove the duplicate PBKDF and Blowfish implementation when no longer used.
- [ ] Verify existing OpenSSH derivation vectors and encrypted-key import tests pass.
