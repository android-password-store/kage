# 17: Replace the ineffective bcrypt overwrite test

**What to build:** bcrypt PBKDF tests verify derivation behavior rather than unrelated array-copy behavior.

**Blocked by:** #07: Replace duplicate bcrypt PBKDF with Bouncy Castle.

**Status:** ready-for-agent

- [ ] Remove the test that only verifies `System.arraycopy` leaves a destination tail unchanged.
- [ ] Retain or add meaningful known-answer coverage for the bcrypt PBKDF implementation in use.
- [ ] Ensure tests exercise requested derivation lengths and validate derived bytes.
