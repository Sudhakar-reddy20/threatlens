# Windows Event Log Analyzer — sample triage notes

Dataset: `sample_logs/security-events.xml` (synthetic)

## Expected triage leads

1. **WELA-001:** Five failed logons (4625) from `192.0.2.80` in a five-minute span. Target account: `administrator`.
2. **WELA-002:** A successful logon (4624) from the same source follows the failures.
3. **WELA-003:** Event 4720 records creation of `temp-user`.
4. **WELA-005:** Event 1102 records that the Security audit log was cleared.

These are intentionally seeded examples. The tool should report leads for analyst validation, not label them as confirmed compromise.

## Analyst questions

- Is the source IP an approved management host, VPN gateway, or scanner?
- Is the logon type expected for this server?
- Was the new account approved and documented?
- Was the audit-log clear event part of authorized maintenance?
- What process, session, and endpoint activity occurred before and after these events?

## Evidence handling

Preserve the original exported XML, record its source and collection time, and analyze a working copy. Do not modify or overwrite the original evidence.
