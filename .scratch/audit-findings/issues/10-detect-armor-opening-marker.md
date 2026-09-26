# 10: Detect armor from its opening marker

**What to build:** Binary age input is not misclassified as armored merely because it contains hyphens in a recipient type or argument.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Identify armor by matching the complete permitted opening marker at the start of input, accounting only for allowed leading whitespace.
- [ ] Leave input in binary mode when the opening marker does not match.
- [ ] Test binary headers containing five hyphens and valid armored input.
