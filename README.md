# PairingLens

PairingLens reviews authorized offline BLE pairing metadata. It accepts a bounded JSON trace containing timestamped Pairing Request/Response SMP metadata, encryption changes, bonding, reconnect, failure, and disconnect events. It reports legacy versus LE Secure Connections indicators, Just Works or candidate authenticated methods, key size and capability mismatch indicators, event timelines, and comparison between traces. Results are explicitly inferred, not a verified device security rating.

```sh
python3 -m pairinglens.cli authorized-trace.json --output review.json
python3 -m pairinglens.cli before.json --compare after.json
```

Each trace is limited to 2 MB and 10,000 events. `pdu_hex` accepts only seven-byte SMP Pairing Request/Response PDUs; key distribution and secret-bearing PDUs are rejected. See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), [HARDWARE.md](HARDWARE.md), [DEPENDENCIES.md](DEPENDENCIES.md), and [VALIDATION_REPORT.md](VALIDATION_REPORT.md).
