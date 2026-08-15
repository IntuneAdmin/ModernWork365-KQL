# Modern Work365 KQL

A collection of KQL (Kusto Query Language) queries and Microsoft Defender XDR / Sentinel custom detection rules for Microsoft 365, Entra ID, and Modern Workplace security monitoring.

This repo is organized by topic, with each subfolder covering a specific monitoring area. New Modern Work-related KQL content will be added over time.

## Modules

### 🔐 Break Glass Account Monitoring

Custom detection rules for monitoring the organization's break glass (emergency access) accounts in Microsoft Defender XDR, without triggering automated remediation that could inadvertently lock out emergency access.

| # | Rule | Severity | Frequency | Table |
|---|------|----------|-----------|-------|
| 1 | Detect the Sign-in with the Break Glass Account | High | Continuous (NRT) | `EntraIdSignInEvents` |
| 2 | Detection-FailedSignin-Threshold (3+/hour) | Medium | Hourly | `EntraIdSignInEvents` |
| 3 | MFA / authentication method & credential changes | High | Hourly | `CloudAppEvents` |
| 4 | Detect Removal from CA Exclusion Group | High | Hourly | `CloudAppEvents` |
| 5 | Detect Deletion or Restore of BG Account | High | Continuous (NRT) | `CloudAppEvents` |

## Key lessons learned (tenant-agnostic, reusable across modules)

- Many Entra ID audit `ActionType` values end with a trailing period (e.g. `"Update user."`, `"Remove member from group."`) — always verify the exact string against live `RawEventData` before finalizing a query.
- Event JSON structure varies by activity type: sign-in/consent events use `TargetResources`; directory management events (user/group) use `ObjectId` (target) + `ModifiedProperties`, with the actor in `AccountObjectId`/`AccountDisplayName`.
- Prefer matching on **Object ID (GUID)** over UPN — a deleted user's UPN gets auto-prefixed with its Object ID, breaking UPN-based substring matches.
- For credential/auth-method changes, filter on the generic `"Included Updated Properties"` field inside `ModifiedProperties` rather than enumerating every possible property name.
- Queries using `summarize` or `mv-expand` disqualify a rule from Continuous (NRT) frequency — Defender falls back to a fixed interval (hourly).
- `CloudAppEvents` ingestion typically lags 15–60 minutes behind the Entra ID audit log UI — check the portal audit log first when validating a test event.
- Defender alert title/description accepts a maximum of 3 distinct column placeholders combined.
- Omit Mailbox entity mapping unless it's genuinely relevant — it can incorrectly map a UPN as a mailbox address and add noise.

## Usage

1. Browse to the relevant module folder.
2. Copy the `.kql` query into Defender → **Advanced Hunting** or a new **Custom detection rule**.
3. Replace tenant-specific placeholders (UPNs, Object IDs, group IDs) with your own values.
4. Configure alert metadata, entity mapping, and MITRE ATT&CK tags as documented in the module README.
5. Test with a controlled event before relying on the rule in production.

⚠️ **Disclaimer:** These queries are provided as-is, based on real-world testing in a specific tenant. Microsoft periodically changes Advanced Hunting schema/table names (e.g. `AADSignInEventsBeta` → `EntraIdSignInEvents`) — always validate against your own tenant's live data before deploying.

## Contributing

New Modern Work-related KQL (Conditional Access, privileged role monitoring, Exchange Online, Teams, etc.) is welcome as new module folders following the same structure: a module README + individual `.kql` files.
