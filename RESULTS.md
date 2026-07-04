# Trap House: Results

Findings from the live deployment. The honeypot has been internet-facing on a
VPS since 2026-06-30, collecting real attacker traffic against the Cowrie SSH
honeypot, the Endlessh tarpit, and the deception web app.

> Data window: 2026-06-30 to 2026-07-04 (early sample). Figures below exclude
> the operator's own test traffic and the internal Docker gateway address.

## Volume

| Metric | Value |
|--------|-------|
| Total events captured | ~3,600 |
| Unique attacker IP addresses | ~175 |
| Distinct sessions | ~630 |
| MITRE ATT&CK techniques observed | 12 |

Traffic breaks down roughly as Cowrie SSH (the large majority), the Endlessh
tarpit, and a smaller set of interactions against the deception web app.

## Most-observed MITRE ATT&CK techniques

| Technique | Name | Hits |
|-----------|------|------|
| T1595.001 | Active Scanning: Scanning IP Blocks | ~800 |
| T1083 | File and Directory Discovery | ~365 |
| T1087 | Account Discovery | ~360 |
| T1049 | System Network Connections Discovery | ~340 |
| T1078 | Valid Accounts | ~280 |
| T1082 | System Information Discovery | ~200 |
| T1059 | Command and Scripting Interpreter | ~180 |
| T1110.001 | Brute Force: Password Guessing | ~170 |

The distribution matches the expected opportunistic-attacker profile: mass
scanning and credential guessing, followed by post-access discovery commands
(`uname`, `whoami`, `ls`, reading `/etc/passwd`) once a weak password lands them
in the Cowrie shell.

## Credential guessing

The usernames attackers tried most were `admin`, `support`, and `root`, which is
consistent with the curated Cowrie `userdb` accepting the planted `admin` decoy
plus common weak `root` passwords. Successful logins (T1078) lead attackers into
the fake shell where the planted `/home/admin/.env` steers them toward the
deception web app.

## Notable attacker behavior

Several source IPs ran full discovery sequences after logging in: enumerating
the filesystem, reading the decoy `.env`, and probing network configuration.
These are the sessions most worth reviewing in the SOC dashboard's session
replay, which reconstructs each attacker's path through the deception layers.

## Dashboard

The custom SOC dashboard visualizes all of the above: a Leaflet attack map of
source-IP geolocations, a MITRE ATT&CK heatmap, per-session replay, and a
filterable event timeline. Reach it over the SSH tunnel at
`http://localhost:8001`.

> Screenshots: add captures of the attack map, MITRE heatmap, and a session
> replay here (`docs/img/`) to make this section self-contained for readers who
> are not running the stack.

## Reproducing these numbers

The `scripts/digest.sh` cron job writes a dated markdown summary (totals, unique
IPs, 24h deltas, top attackers by risk score, technique counts, recent events)
to `digests/`. This report is a curated snapshot of that data.
