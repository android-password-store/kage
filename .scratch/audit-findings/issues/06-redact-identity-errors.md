# 06: Redact identity input from parse errors

**What to build:** Invalid identity input can be diagnosed without exposing secret key material in exception messages or logs.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Replace raw identity-line interpolation with a line number or redacted identity type.
- [ ] Preserve enough non-sensitive context to identify the parse failure.
- [ ] Test that malformed secret-key input is absent from the resulting exception message.
