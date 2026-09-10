# Trusted by Default

- **Platform:** TryHackMe
- **URL:** https://tryhackme.com/room/trustedbydefault
- **Date started:** 2026-09-10
- **Date completed:** Paused mid-session — Q1-10 answered and accepted, room likely has more tasks remaining
- **Difficulty:** Medium (log-analysis / investigation room, not an exploitation room)
- **Time spent:** ~1 session, evening of 2026-09-10

## Summary

A "blue team" investigation room: instead of breaking into a system, the job is to read through logs already collected in Splunk (a log search platform) and reconstruct what an attacker did. Scenario: acting as an analyst for TSS (a fictional security firm) investigating a suspected compromise of a service account (an automated login used by software, not a person) at client "Aurora Retail."

## Scenario / Case Briefing

- Role: Assigned Analyst, reporting to Mara Okafor (Incident Response Lead), TSS (THM Security Services)
- Client: Aurora Retail Group (Retail industry)
- Case: "Trusted By Default" — Active investigation, High priority
- Lab machine / Splunk target: 10.113.139.34
- Lab access URL: https://10-113-139-34.reverse-proxy.cell-prod-eu-central-1b.vm.tryhackme.com
- Interface: Splunk Search & Reporting app (evidence pre-indexed, no upload/config needed)

### Situation Report

Aurora's security team escalated unusual login activity tied to a trusted service account normally used for predictable, automated customer-portal operations. That activity appeared alongside suspicious website requests, endpoint telemetry, and outbound network traffic — possible wider compromise.

Goal: determine whether the service account was abused, how the attacker moved from the public website into the internal network, and whether data was collected or moved out.

### Mission Parameters

1. Establish whether the service account shows evidence of compromise
2. Determine how activity on the public portal led into command execution (getting code to actually run on a server)
3. Assess whether the attacker accessed credentials or moved laterally (used one compromised account/machine to reach others)
4. Identify any staging or transfer activity linked to the incident (data being gathered or moved out)
5. Confirm what the evidence supports — avoid unsupported conclusions

## Investigation Guidance (from room)

- Start broad enough to compare normal vs. abnormal activity
- Inspect returned fields before adding filters
- Use the value recovered in one question as the pivot for the next
- Use source-specific endpoint fields instead of Splunk's ingestion host field
- Use decimal bytes for exact transfer totals unless a question specifies another unit
- Main incident activity occurs on 11 August 2026

## Task Questions

1. URI path of the unusual POST request that starts the incident (format `/***/***.***`)
2. Source IP of that POST request
3. Non-system account that received a batch logon shortly before the request, on AUR-WEB01
4. Windows logon type recorded for that batch logon
5. Privileged group modified for the Portal Application Service account (after web-server activity)
6. User who performed that group-membership change
7. Non-built-in account generating both network + remote-interactive logons on the file server shortly after the group change
8. Numeric LogonType for the remote-interactive session
9. Destination IP for the sustained RDP connection (pivoting from POST source IP), vs. reset attempts
10. resp_bytes value for that sustained RDP connection (decimal bytes, digits only)

(more tasks may follow after these)

## Recon

Splunk organizes data into **indexes** (top-level buckets) and **sourcetypes** (the format/origin of the data within an index). Found the available data with `* | stats count by index sourcetype`:

| Index | Sourcetype | What it is | Relevance |
|---|---|---|---|
| web | iis | Website server access logs | Q1-2, the suspicious request |
| wineventlog | XmlWinEventLog:Security | Windows login/security logs | Q3-8, logons/group changes |
| sysmon | XmlWinEventLog:Microsoft-Windows-Sysmon/Operational | Detailed Windows process/activity logs | Tracing what actually ran on the machines |
| network | zeek:conn | Network connection records (like a phone bill: who talked to whom, for how long, how much data) | Q9-10, RDP connections, bytes transferred |
| network | zeek:http, zeek:dns, zeek:files, zeek:ssl, zeek:x509, aurora:webdav | Other network traffic logs | Supporting evidence |

Note: `tstats`/`eventcount` (fast metadata-only search commands) returned 0 events in this lab — likely disabled in this environment. A plain `*` search (match everything) piped into `stats`/`table` worked fine instead. Also: the `stats by` clause wants fields separated by spaces, not commas — a comma silently produced 0 results instead of an error.

## Investigation Findings

### Q1-2: The suspicious request

- Searched the web logs (`index=web sourcetype=iis`) for POST requests (a request that sends/submits data, as opposed to GET which just retrieves a page) on 11 Aug 2026 — only one existed all day
- Time: 2026-08-11 09:16:31, web server: AUR-WEB01
- Page requested (URI path): `/portal/status.aspx`
- Extra data sent with it (query string): `ticket=SR-48228`
- Requester's IP address: `10.81.73.36`
- Web server's IP: `10.81.70.212`
- Claimed software making the request (User-Agent header — easily faked, so treated as a clue, not proof): `Aurora-Remote-Support/1.6`
- Time the server took to respond: 1362ms, much slower than normal page loads (~100-230ms) — consistent with the server doing extra work, e.g. processing a malicious payload smuggled in the `ticket` value

### Q3-4: Login shortly before the request

Windows records every login as **Event ID 4624** ("An account was successfully logged on"), and tags it with a **LogonType** number describing how it happened (3 = over the network, 4 = "batch" — typically an automated/scheduled task rather than a person typing a password, 5 = a service starting up, 10 = a full remote-desktop-style session).

- Searched: logins on AUR-WEB01, type 4 (batch), in the run-up to 09:16:31 → exactly one match
- 2026-08-11 09:15:28, account: **svc-webapp**, LogonType **4** (batch/automated)
- This happened 63 seconds before the suspicious request — consistent with the web request triggering an automated task that logged this account in, i.e. this is likely the "trusted service account" mentioned in the briefing
- Note: Windows logs list the machine name inside the log entry itself (`<Computer>` field), which Splunk exposes as `endpoint`/`endpoint_fqdn`. Splunk's own generic `host` field (whichever server forwarded the log) isn't always the same machine, so `endpoint` is the reliable one to filter on

### Q5-6: Account given extra privileges

Windows logs adding someone to a security group (a set of accounts sharing the same permissions) as its own event — **Event ID 4728** ("member added to a security-enabled global group").

- Found one such event on the domain controller (AUR-DC01), at 09:16:43 — 12 seconds after the batch login above
- Account added: the AD (Active Directory — Windows' central directory of users/computers) entry for "Portal Application Service", i.e. `svc-webapp`
- Group it was added to: **FS-Admins** (a privileged, file-server-administrator group — this is the escalation)
- Who performed the change: **a.ng**
- Note: a plain text search for "svc-webapp" did *not* find this event, because the account was logged by its full directory path (`CN=Portal Application Service,OU=Service Accounts,DC=aurora,DC=local`), not its short login name. Lesson: search by the event's structure (its ID number, its fields) rather than assuming how a value will be spelled out in the log.
- Reading: the attacker escalated `svc-webapp` into a privileged group, setting up the next step (reaching the file server with admin-level access)

### Q7-8: File server logins

- Searched logins (again Event ID 4624) on the file server (AUR-FS01) in the minutes after the group change
- `svc-webapp` shows up twice: once as LogonType 3 (network) at 09:17:00, then LogonType **10** (RemoteInteractive — a full remote-desktop-style session) one second later, both from IP **10.81.73.36** — the same IP as the original suspicious request
- Account: **svc-webapp**
- Remote-desktop-style LogonType number: **10**
- Reading: this confirms lateral movement — the now-escalated account was used, from the attacker's own IP, to fully log into a second machine

### Q9-10: The network connection itself

Searched the network connection records (`zeek:conn`) for traffic from `10.81.73.36` to port 3389 (the standard port for RDP — Windows' remote desktop protocol). Found 3 connection attempts:

- Two were reset almost instantly (`conn_state=RSTO`, under 1ms, 0 bytes exchanged) — failed/rejected attempts, to `10.81.112.251` and `10.81.70.212`
- One lasted 17.5 seconds and moved real data: destination **10.81.112.251**, encrypted (RDP running over TLS), 13,018 bytes sent, **181,717 bytes returned** (`resp_bytes` = bytes sent back by the destination machine)
- Destination IP of the real connection: **10.81.112.251**
- Bytes returned (`resp_bytes`): **181717**

## Attack Chain Summary (Q1-10)

1. **Initial access:** one unusual POST request to `/portal/status.aspx?ticket=SR-48228` from `10.81.73.36`, disguised with a fake "remote support" identifier, taking far longer than normal to process — likely a payload hidden in the `ticket` value
2. **Execution:** the `svc-webapp` service account logs in via an automated/batch process on the web server, 63 seconds after the request — the request appears to have triggered a scheduled task
3. **Privilege escalation:** `svc-webapp` gets added to the privileged **FS-Admins** group by user `a.ng`, 12 seconds later
4. **Lateral movement:** using the same attacker IP, `svc-webapp` logs into the file server — first a network login, then a full remote-desktop-style session
5. **Sustained connection:** a real (not rejected) encrypted connection from `10.81.73.36` to `10.81.112.251` over the remote-desktop port, lasting 17.5 seconds with 181,717 bytes sent back — the one connection that wasn't immediately shut down

## Answers Submitted

| # | Question | Answer | Status |
|---|---|---|---|
| 1 | Suspicious POST URI path | `/portal/status.aspx` | accepted |
| 2 | Source IP of POST | `10.81.73.36` | accepted |
| 3 | Account with batch logon | `svc-webapp` | accepted |
| 4 | Batch logon type | `4` | accepted |
| 5 | Privileged group modified | `FS-Admins` | accepted |
| 6 | User who made the change | `a.ng` | accepted |
| 7 | Account w/ network + remote-interactive logons | `svc-webapp` | accepted |
| 8 | Remote-interactive LogonType | `10` | accepted |
| 9 | Sustained RDP destination IP | `10.81.112.251` | accepted |
| 10 | resp_bytes of sustained RDP connection | `181717` | accepted |

## Tools & Techniques Used

- Splunk search (its query language is called SPL — Search Processing Language): `stats` (summarize/count), `table` (format as columns), `sort`, and field-based filtering across multiple indexes/sourcetypes
- Correlating Windows security events by their numeric Event ID (4624 = logon, 4728 = added to a group) instead of guessing at text to search for
- Reading Zeek network connection logs (Zeek is a network-traffic logging tool; its field names here were already normalized by Splunk's CIM — Common Information Model, a standard naming scheme — into plain names like `src`, `dest`, `dest_port`, `resp_bytes`) to tell a real connection apart from rejected attempts
- Cross-source pivoting: taking a value found in one log (an IP address, an account name) and using it as the search filter in the next log source

## Lessons Learned

- **Inspect fields before filtering.** A couple of fast/advanced search commands (`tstats`, `eventcount`) silently returned nothing in this lab — likely disabled. A plain "match everything" search plus `stats`/`table` worked reliably instead.
- **Watch punctuation in queries.** `stats by` wants fields separated by spaces, not commas — a misplaced comma silently produced zero results rather than a clear error.
- **Splunk's generic `host` field isn't always the actual machine.** For Windows logs here, the real computer name lived inside the log entry itself, exposed by Splunk as `endpoint`/`endpoint_fqdn` — that was the reliable field to filter on.
- **Don't assume how a value will be written in a log.** A plain-text search for the account name missed a key event because that log recorded the account by its full directory path instead of its short name. Searching by the event's ID/structure instead of guessing exact wording is more reliable.
- **For network logs, connection state plus duration/bytes tells you what's real.** An instantly-reset, zero-byte connection is a failed attempt; a connection with real duration and data exchanged is an actual session — regardless of how it eventually ended.
