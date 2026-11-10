# Security

Use only traces collected with authorization. The parser rejects raw SMP PDUs other than Pairing Request/Response metadata, so it does not extract or store pairing keys. Do not include key bytes in freeform trace fields. No active pairing, interception, impersonation, forced disconnect, credential extraction, MITM test, or decryption exists. Retain local trace and report files only for the authorized review period. Indicators alone do not establish actual pairing strength.
