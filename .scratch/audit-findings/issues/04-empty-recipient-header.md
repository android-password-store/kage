# 04: Handle headers with no recipient stanzas

**What to build:** Decryption of a header with no recipients returns a defined format or identity error rather than an unrelated collection exception.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Either reject empty recipient lists during parsing or handle them explicitly during identity unwrap.
- [ ] Return the established invalid-header or incorrect-identity exception type.
- [ ] Test parsing and decryption of a syntactically empty recipient list.
