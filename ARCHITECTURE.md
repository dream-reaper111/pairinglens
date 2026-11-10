# Architecture

The CLI reads one or two bounded JSON metadata traces. The parser accepts selected non-secret SMP Pairing Request/Response fields, validates timezone-bearing timestamps, and sorts a local event timeline. The assessment compares auth flags and IO capability metadata to produce cautious method and downgrade indicators. It does not verify user interaction, negotiated security level, or peripheral enforcement. The output supports an analyst's manual review and trace comparison. No database or live adapter is used.
