# Trap House: Final Results

Trap House completed its live collection window and is now archived. The public VPS was powered off after the final digest and evidence capture.

Full report: [docs/final-report.md](docs/final-report.md)

## Final collection window

The sensor ran from 2026-06-30 05:31:53 UTC to 2026-07-31 16:43:02 UTC. The window lasted 31 days, 11 hours, 11 minutes, and 9 seconds.

Final frozen totals:

- 298,928 events
- 2,421 unique source IPs
- 66,299 sessions
- 12 MITRE ATT&CK technique IDs observed
- 54,143 authentication attempts
- 435 accepted decoy logins
- 437 file uploads
- 226 command execution events
- 266 proxy request and data events

The stored-row sensor acceptance ratio was 0.8034 percent. A Cowrie-only login outcome calculation gives 0.7970 percent. Neither figure is a real compromise rate because accepted credentials entered an emulated shell.

## Strongest finding: repeated Outlaw or RedTail chain

Source `130.12.180.51` produced the most valuable activity in the dataset:

- 992 events across 75 sessions
- 75 accepted decoy logins
- 65 persistence and dropper command sequences
- 423 file uploads
- Repeated `clean.sh`, `setup.sh`, and architecture-specific `redtail` uploads
- SSH key persistence protected with `chattr +ai`
- Architecture detection with `uname -mp`
- Competitor miner removal and cron cleanup

A second source, `45.148.10.68`, replayed the same filenames and command pattern in two sessions. This supports shared tooling or campaign reuse. It does not prove common operator identity.

The honeypot recorded the commands and uploads but did not execute the binaries. The initial `redtail.x86_64` sample matches ThreatFox IOC 1820703 with high reported confidence:

https://threatfox.abuse.ch/ioc/1820703

The broader behavior is consistent with public analysis of Outlaw Linux malware:

https://www.elastic.co/security-labs/outlaw-linux-malware

## Detection lessons

- Alert on successful SSH authentication followed by `uname -mp` or similar architecture discovery.
- Alert on `authorized_keys` changes combined with `chattr +ai`.
- Detect cleanup of cron locations, shell startup files, and temporary directories after login.
- Detect shell transfer chains that fall back from `curl` to `wget` to `/dev/tcp`.
- Treat `support`, `cassandra`, `a2`, and other application service accounts as high value credential targets.
- Rank post-authentication uploads and commands above raw brute force volume.
- Add T1090 mapping for proxy behavior and retain destination IP and port as structured fields.

## Data quality and limitations

T1049 and T1087 counts are inflated because the current mapper tags some pre-authentication events. They are retained for transparency but are not presented as genuine post-compromise discovery counts.

Cowrie is low interaction. The dataset proves attempted delivery, persistence preparation, and command input. It does not prove successful binary execution, C2 contact, persistence on a real host, or cryptocurrency mining.

Source IPs identify network origins, not people or organizations. Cloud providers, NAT, proxies, and compromised systems can obscure attribution.

## Archived evidence

The frozen database, compressed JSON logs, host inventory, and matching SHA256 records are stored locally under:

`evidence/final-2026-07-31/frozen/`

The evidence directory is gitignored by design. The frozen database passed SQLite integrity checking, and the remote and local artifact hashes matched.

Selected dashboard and case study assets remain in the repository:

![Attack map](docs/img/attack-map.png)

![MITRE heatmap](docs/img/mitre-heatmap.png)

![Top attackers](docs/img/top-attackers.png)

![Outlaw session replay](docs/img/session-replay-outlaw.png)

![Outlaw kill chain](docs/img/outlaw-killchain.gif)

![Full dashboard](docs/img/dashboard-full-with-outlaw-replay.png)

## Closure

The production compose stack was stopped and removed. No monitored honeypot listeners remained after shutdown. The VPS was then powered off, and a follow-up SSH connection timed out.

The project is now an analysis and reproducibility artifact rather than an active public sensor.
