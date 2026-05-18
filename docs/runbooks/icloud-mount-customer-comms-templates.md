# iCloud Mount Customer Communications Templates (ICLOUD-053)

Use these templates during incidents involving iCloud mounts. Keep messages factual, avoid blame, and do not include sensitive credential details.

## Comms cadence policy

- **P1 incidents:** initial message within 15 minutes of incident declaration, then updates every 30 minutes.
- **P2 incidents:** initial message within 60 minutes, then updates every 2 hours.
- **Security incidents:** initial security advisory as soon as containment actions are started.

## Template 1 — Initial advisory (provider outage/degradation)

> We are investigating elevated errors affecting iCloud mount operations in Files. Some mounted iCloud paths may be temporarily read-only or unavailable while mitigation is in progress. Non-mounted file paths continue to operate normally. Next update by: **{{next_update_time_utc}}**.

## Template 2 — Initial advisory (auth storm / reconnect required)

> We are seeing elevated iCloud authentication failures and are actively mitigating. Some users may be prompted to reconnect iCloud mounts. If prompted, please open Files → Connect iCloud and complete verification. Next update by: **{{next_update_time_utc}}**.

## Template 3 — Security advisory (credential compromise suspected)

> We detected suspicious activity related to iCloud mount credentials and proactively revoked affected mount sessions. As a precaution, impacted users must reconnect iCloud mounts and complete verification. We are continuing investigation and will provide a detailed follow-up.

## Template 4 — Mitigation progress update

> Mitigation is in progress. Current impact: **{{impact_summary}}**. Current status: **{{status}}** (`active`/`degraded`/`unavailable`/`reauth_required`). We continue to monitor auth failures, provider errors, and mount recovery metrics. Next update by: **{{next_update_time_utc}}**.

## Template 5 — Resolution notice

> Mitigation is complete and iCloud mount operations have returned to expected service levels. We are monitoring closely and will publish a post-incident summary covering impact, timeline, and preventive actions.

## Fill-in checklist before sending

- Incident ID: `{{incident_id}}`
- Audience: `{{customer_segment}}`
- Blast radius: `{{tenants_or_regions}}`
- Customer action required: `{{yes/no + action}}`
- Next update timestamp in UTC: `{{next_update_time_utc}}`
- Approved by IC/Comms owner: `{{name}}`

## Do/Don't

### Do
- Include expected next-update time.
- State whether customer action is required.
- Use neutral language focused on observed impact and mitigation status.

### Don’t
- Share secret identifiers, auth payloads, or internal-only implementation details.
- Promise specific recovery times before engineering confirms.
- Omit customer-action instructions when reconnection is required.
