# Trap House Final Collection Report

## Executive summary

Trap House was an internet-facing, multi-layer deception honeypot operated on a Hetzner VPS from 2026-06-30 05:31:53 UTC to 2026-07-31 16:43:02 UTC. The collection window lasted 31 days, 11 hours, 11 minutes, and 9 seconds.

The final frozen dataset contains:

<table>
<thead><tr><th>Metric</th><th>Result</th></tr></thead>
<tbody>
<tr><td>Events</td><td>298,928</td></tr>
<tr><td>Unique source IPs</td><td>2,421</td></tr>
<tr><td>Sessions</td><td>66,299</td></tr>
<tr><td>MITRE ATT&amp;CK technique IDs observed</td><td>12</td></tr>
<tr><td>Authentication attempts</td><td>54,143</td></tr>
<tr><td>Decoy authentication successes</td><td>435</td></tr>
<tr><td>File uploads</td><td>437</td></tr>
<tr><td>Command execution events</td><td>226</td></tr>
<tr><td>Proxy request and data events</td><td>266</td></tr>
</tbody></table>

The strongest finding was not the volume of automated SSH noise. It was the repeated Outlaw or RedTail style intrusion chain. Source 130.12.180.51 authenticated successfully 75 times, issued 65 persistence and dropper command sequences, and uploaded 423 files. The sequence included competitor removal, cron cleanup, SSH key persistence protected with an immutable file attribute, architecture detection, and deployment of an architecture-specific RedTail binary. A second source, 45.148.10.68, replayed the same file and command pattern in two sessions. The evidence supports a shared campaign or reused tooling, but source IP overlap alone does not prove common operator identity.

The sensor remained safe throughout the collection period. Cowrie accepted the interactions and recorded the uploaded material, but did not execute the binaries. The webshell sandbox also kept commands inside an in-memory fake filesystem. The VPS was frozen, the compose stack was removed, the host was powered off, and a follow-up SSH check timed out as expected.

## Collection and evidence handling

The deployment consisted of nine containers across an attacker-facing Docker network and an internal network. The external layer exposed Cowrie SSH and Telnet, Endlessh, and the FastAPI deception gateway. The internal layer contained the log shipper, MITRE mapper, Loki, Grafana, frontend, and scoped Docker socket proxy.

The final collection procedure was:

1. Run the live digest over SSH.
2. Take a consistent SQLite backup with the SQLite backup API rather than copying a live database file with an active WAL.
3. Archive the remote JSON logs.
4. Record host, container, listener, and database state.
5. Stop the production compose stack.
6. Run the digest again against the frozen database.
7. Take a second SQLite backup and log archive after shutdown.
8. Compare remote and local SHA256 values.
9. Power off the VPS and verify that SSH no longer responded.

The final frozen evidence is stored locally at:

`evidence/final-2026-07-31/frozen/`

The frozen database passed `PRAGMA integrity_check` with result `ok`. The remote and local hashes matched:

<table>
<thead><tr><th>Artifact</th><th>SHA256</th></tr></thead>
<tbody>
<tr><td>`trap-house.db`</td><td>`a171d728e6b0f7fbf0728650b31663710b99e439d99ddc315363bd5867acbb18`</td></tr>
<tr><td>`logs.tgz`</td><td>`bfa074ecd2ff1704d356bc93e54e274cf61c47ce7c4eb37d75b0414e5036f5b0`</td></tr>
</tbody></table>

The evidence directory is gitignored. This is intentional. The repository keeps selected malware samples and report assets out of version control, while the report records the final evidence path and hashes.

## Volume and traffic profile

Cowrie produced almost all events. Endlessh captured 1,373 tarpit connections, while the deception gateway produced 44 events.

<table>
<thead><tr><th>Service</th><th>Events</th></tr></thead>
<tbody>
<tr><td>Cowrie</td><td>297,511</td></tr>
<tr><td>Endlessh</td><td>1,373</td></tr>
<tr><td>Deception gateway</td><td>44</td></tr>
</tbody></table>

The most common event types were session lifecycle and SSH negotiation records. The higher-value interaction events were less frequent but more informative.

<table>
<thead><tr><th>Event type</th><th>Count</th></tr></thead>
<tbody>
<tr><td>Session disconnect</td><td>64,578</td></tr>
<tr><td>Session connect</td><td>64,483</td></tr>
<tr><td>Client version</td><td>57,218</td></tr>
<tr><td>Client key exchange</td><td>55,247</td></tr>
<tr><td>Authentication attempt</td><td>54,143</td></tr>
<tr><td>Tarpit connection</td><td>1,373</td></tr>
<tr><td>File upload</td><td>437</td></tr>
<tr><td>Authentication success</td><td>435</td></tr>
<tr><td>Command execution</td><td>226</td></tr>
<tr><td>Proxy request</td><td>143</td></tr>
<tr><td>Proxy data</td><td>123</td></tr>
<tr><td>File download</td><td>7</td></tr>
</tbody></table>

The busiest days were 2026-07-09 with 74,900 events, 2026-07-30 with 39,404 events, and 2026-07-10 with 38,075 events. The single largest source, 5.31.5.95, generated 87,818 events, 29.38 percent of the entire dataset, but its activity was concentrated into a short burst between 2026-07-09 and 2026-07-10.

## Authentication analysis

There were 54,143 authentication attempts and 435 decoy successes. The stored-row sensor acceptance ratio was 0.8034 percent. A Cowrie-only login outcome calculation, using 54,099 failed Cowrie logins plus 435 successful Cowrie logins, gives 0.7970 percent. The difference comes from 44 deception-gateway authentication rows that do not contain a raw Cowrie login event ID. Neither figure is a real compromise rate. Cowrie intentionally accepted selected credentials and routed attackers into the emulated shell.

The most targeted usernames were:

<table>
<thead><tr><th>Username</th><th>Attempts</th><th>Source IPs</th><th>Decoy successes</th><th>Success IPs</th></tr></thead>
<tbody>
<tr><td>root</td><td>44,432</td><td>409</td><td>362</td><td>141</td></tr>
<tr><td>ubuntu</td><td>1,237</td><td>39</td><td>0</td><td>0</td></tr>
<tr><td>support</td><td>1,078</td><td>185</td><td>31</td><td>3</td></tr>
<tr><td>admin</td><td>523</td><td>276</td><td>36</td><td>11</td></tr>
<tr><td>rdrct</td><td>480</td><td>1</td><td>0</td><td>0</td></tr>
<tr><td>guest</td><td>207</td><td>145</td><td>0</td><td>0</td></tr>
</tbody></table>

The `support` account remains notable because 31 accepted decoy logins came from only three source IPs. That concentration is more useful for detection engineering than the global success rate. It suggests repeated use of a credential pair or a tightly reused wordlist.

The raw success table also contains three malformed values that resemble protocol payloads or an HTTP request rather than normal usernames. They are retained in the database, but excluded from clean username interpretation. This is a data quality signal from exposed services receiving unexpected input, not evidence of a successful account login.

## MITRE ATT&CK coverage

The mapper observed 12 technique IDs. The raw counts are shown below, with an important qualification.

<table>
<thead><tr><th>Technique</th><th>Name in mapper</th><th>Hits</th><th>Evidence quality</th></tr></thead>
<tbody>
<tr><td>T1595.001</td><td>Active Scanning</td><td>65,856</td><td>Strong for scan activity</td></tr>
<tr><td>T1049</td><td>System Network Connections Discovery</td><td>55,247</td><td>Mapper artifact in pre-auth data</td></tr>
<tr><td>T1087</td><td>Account Discovery</td><td>55,113</td><td>Mapper artifact in pre-auth data</td></tr>
<tr><td>T1110.001</td><td>Brute Force</td><td>54,143</td><td>Strong for password guessing</td></tr>
<tr><td>T1105</td><td>Ingress Tool Transfer</td><td>459</td><td>Strong for uploads and transfer patterns</td></tr>
<tr><td>T1078</td><td>Valid Accounts</td><td>435</td><td>Strong as decoy acceptance telemetry</td></tr>
<tr><td>T1082</td><td>System Information Discovery</td><td>282</td><td>Strong when tied to commands such as `uname`</td></tr>
<tr><td>T1083</td><td>File and Directory Discovery</td><td>268</td><td>Strong when tied to filesystem commands</td></tr>
<tr><td>T1021</td><td>Remote Services</td><td>266</td><td>Useful service interaction signal</td></tr>
<tr><td>T1059</td><td>Command and Scripting Interpreter</td><td>228</td><td>Strong for command input</td></tr>
<tr><td>T1071.001</td><td>Application Layer Protocol</td><td>15</td><td>Useful when tied to HTTP download commands</td></tr>
<tr><td>T1110.004</td><td>Credential Stuffing</td><td>2</td><td>Strong where tool signatures matched</td></tr>
</tbody></table>

T1049 and T1087 are inflated by the current mapper because it tags pre-authentication events such as key exchange and authentication attempts. Those counts should not be presented as tens of thousands of real post-compromise discovery actions. The reliable post-authentication signal is the smaller set of command, upload, and accepted-session events. This distinction is preserved here rather than hidden.

## Case study: repeated Outlaw or RedTail intrusion chain

### Primary source

Source `130.12.180.51` was first seen at `2026-06-30T07:05:52Z` and last seen at `2026-07-31T04:52:25Z`.

<table>
<thead><tr><th>Metric</th><th>Result</th></tr></thead>
<tbody>
<tr><td>Events</td><td>992</td></tr>
<tr><td>Sessions</td><td>75</td></tr>
<tr><td>Accepted decoy logins</td><td>75</td></tr>
<tr><td>Commands</td><td>65</td></tr>
<tr><td>File uploads</td><td>423</td></tr>
<tr><td>Distinct event types</td><td>9</td></tr>
<tr><td>Top username</td><td>root</td></tr>
</tbody></table>

The source replayed the same chain across many sessions. The command sequence contained the following behavior:

1. Stop and disable an existing `c3pool_miner` service.
2. Remove persistence artifacts from cron locations and shell startup files.
3. Clear temporary directories and kill competing processes using deceptive names such as `systemtd` and `/bin/-bash`.
4. Detect the host architecture with `uname -mp`.
5. Create or modify `~/.ssh/authorized_keys`.
6. Apply `chattr +ai` to make the key file immutable.
7. Copy the matching `redtail` binary to a writable executable directory.
8. Execute the architecture-matched binary in SSH mode.
9. Delete the uploaded files after deployment.

This is a complete observed delivery and persistence chain, but not a confirmed successful malware execution. Cowrie recorded the commands and uploads without executing the binaries. The correct conclusion is that the attacker attempted deployment against the sensor and reached the execution step inside the emulation boundary.

The file set expanded during the month. The source repeatedly uploaded `clean.sh`, `setup.sh`, `redtail.arm7`, `redtail.arm8`, `redtail.i686`, and `redtail.x86_64`. A `redtail.riscv` file appeared from 2026-07-16 onward. The database records multiple hashes for several architecture variants, which indicates changing payload builds or repackaging rather than one static sample.

### Secondary matching source

Source `45.148.10.68` produced two sessions, two accepted root logins, 14 uploads, and two commands. It replayed the same `clean.sh`, `setup.sh`, and architecture-specific `redtail` filenames. This is strong evidence of shared tooling or campaign reuse. It is not enough to attribute both sources to one operator without additional infrastructure or cryptographic evidence.

### Malware corroboration

The initial captured `redtail.x86_64` sample has SHA256:

`59c29436755b0778e968d49feeae20ed65f5fa5e35f9f7965b8ed93420db91e5`

ThreatFox IOC 1820703 associates that hash with RedTail and reports high confidence at 85 percent:

https://threatfox.abuse.ch/ioc/1820703

Independent reporting on Outlaw describes the same broad behavior seen in this sensor data: SSH brute force, SSH key and cron persistence, competitor removal, and modified XMRig based mining tooling:

https://www.elastic.co/security-labs/outlaw-linux-malware

The repository also contains the selected captured scripts and binaries used for the original static review. No sample was executed by the honeypot or during report preparation.

## Secondary bash downloader campaign

A separate pattern appeared in command input and should not be merged into the Outlaw case study. The stagers used:

- `curl` first, followed by `wget` as a fallback.
- Bash `/dev/tcp` as a third transfer method.
- Random files under `/tmp`.
- A fixed payload write size of 3,716,336 bytes.
- A large encoded argument passed to the downloaded binary.
- A marker file named `.opass`.

This pattern maps cleanly to T1105 and T1059. It demonstrates why detection should watch for shell processes making outbound connections on arbitrary ports, not only for `curl` and `wget` binaries.

The sensor logged these commands but did not fetch or execute the payload. It separately recorded 7 file-download events from two sources across five URLs and six hashes. The fixed size, fallback chain, and encoded argument are behavioral indicators, not proof of the payload's final malware family.

## Proxy and relay abuse

The deception layer recorded 266 explicit proxy request or proxy data events. It also recorded 90 unmapped direct TCP fingerprint events. These categories are kept separate below:

<table>
<thead><tr><th>Destination</th><th>Explicit proxy events</th><th>Direct TCP fingerprint events</th><th>Sessions</th><th>Interpretation</th></tr></thead>
<tbody>
<tr><td>8.8.8.8:443</td><td>132</td><td>66</td><td>66</td><td>Repeated HTTPS relay attempts</td></tr>
<tr><td>141.101.90.1:3478</td><td>48</td><td>24</td><td>24</td><td>STUN or TURN relay attempts</td></tr>
<tr><td>1.1.1.1:53</td><td>58</td><td>0</td><td>29</td><td>DNS forwarding attempts</td></tr>
<tr><td>77.88.21.158:25</td><td>20</td><td>0</td><td>20</td><td>SMTP forwarding attempts</td></tr>
<tr><td>64.89.162.38:80</td><td>6</td><td>0</td><td>3</td><td>HTTP forwarding attempts</td></tr>
<tr><td>185.242.3.121:80</td><td>2</td><td>0</td><td>1</td><td>HTTP forwarding attempt</td></tr>
</tbody></table>

The largest individual source behaviors were `195.178.110.137` to `8.8.8.8:443` with 132 explicit proxy events and 66 direct TCP fingerprint events, `45.148.10.121` to `141.101.90.1:3478` with 48 explicit proxy events and 24 direct TCP fingerprint events, and `176.53.159.196` to `1.1.1.1:53` with 58 explicit proxy events. Additional SMTP relay attempts targeted port 25 on a remote destination. These events show attackers testing whether the deception service can be repurposed as an outbound relay. The current MITRE mapper does not assign T1090 to this behavior. That is a clear future improvement if the sensor is ever redeployed.

## Dominant automated noise

The highest-volume sources were not necessarily the most interesting.

<table>
<thead><tr><th>Source</th><th>Events</th><th>Sessions</th><th>Profile</th></tr></thead>
<tbody>
<tr><td>5.31.5.95</td><td>87,818</td><td>17,565</td><td>High-volume automated scanner and brute forcer</td></tr>
<tr><td>144.91.70.9</td><td>36,565</td><td>8,443</td><td>Large repeated SSH campaign</td></tr>
<tr><td>101.201.76.235</td><td>21,302</td><td>4,259</td><td>Root-only brute force, no post-auth behavior</td></tr>
<tr><td>45.148.10.239</td><td>15,692</td><td>3,135</td><td>Repeated `a2` targeting and post-auth activity</td></tr>
<tr><td>92.118.39.78</td><td>15,528</td><td>3,136</td><td>Repeated `a2` targeting and post-auth activity</td></tr>
</tbody></table>

The contrast is important. 101.201.76.235 generated a large amount of brute-force telemetry but did not progress to uploads or commands. 130.12.180.51 generated fewer events but produced the most valuable evidence because it crossed the authentication boundary and attempted a full malware deployment chain.

## Defensive takeaways

1. Alert on successful SSH authentication followed by architecture discovery, especially `uname -mp` or `uname -s -m`.
2. Alert on `authorized_keys` changes combined with `chattr +ai`. The immutable attribute is a high-signal persistence indicator.
3. Alert on shell activity that removes cron entries, cleans `/tmp`, or kills processes with names that imitate system binaries.
4. Detect a transfer fallback chain involving `curl`, `wget`, and `/dev/tcp`, especially when the destination port is not a standard web port.
5. Treat service accounts such as `support`, `cassandra`, `a2`, and `rdrct` as high-value credential monitoring targets. The observed wordlists extended beyond `root` and common distribution accounts.
6. Separate brute-force volume from post-authentication risk. A lower-volume source that uploads files and executes commands deserves more attention than a noisy scanner that never authenticates.
7. Add explicit T1090 mapping for proxy requests and preserve destination IP and port as first-class fields.
8. Keep the sensor non-executing. The deception value came from capturing the complete attempted chain without turning the VPS into a malware host.

## Schema and mapper caveats

The database contains 66,299 rows in the sessions table, while 66,222 distinct non-null event session IDs appear in the events table. The difference is 77 zero-event session rows created by the services. Forty-four deception-gateway authentication events have null session IDs. These are schema accounting details, not missing attack evidence.

Event timestamps use two UTC serializations: `Z` for 297,555 rows and `+00:00` for 1,373 rows. Both represent UTC, but analysis tooling should normalize them before sorting or grouping.

The mapper processed all 298,928 events. The enriched techniques table contains 232,314 rows, while 122,115 processed events have no matching technique row. This is expected for events that do not match a configured rule. T1049 and T1087 remain inflated by pre-authentication mapping, as described above.

## Limitations

- Cowrie is low interaction. It cannot prove that the uploaded binaries would execute successfully on a real host, reach C2, establish persistence, or mine cryptocurrency.
- The system records source IP addresses, not human or organizational attribution. Cloud hosting, NAT, proxies, and compromised infrastructure can all obscure the true operator.
- T1049 and T1087 are currently inflated by mapper behavior on pre-authentication events.
- The deception gateway generated only 44 events, so the web-facing layer contributed little compared with SSH.
- The final frozen archive contains the SQLite snapshot and JSON logs. It does not place the complete remote container download volume into version control. Selected captured samples remain in the local, gitignored `evidence/` directory.
- Threat intelligence matches support malware-family identification, but they do not independently prove that every variant uploaded during the window was identical.

## Closure status

The live deployment is closed.

- Production compose stack: stopped and removed.
- Honeypot listeners after compose shutdown: none observed on the monitored ports.
- Database integrity: `ok`.
- Remote and local evidence hashes: matched.
- VPS power state: powered off.
- Post-shutdown SSH verification: timed out, confirming that the host was no longer reachable.

The project is now an analysis and reproducibility artifact rather than an active public sensor. That is the correct stopping point. The collection produced enough signal for a strong portfolio case study, while leaving the host offline prevents unnecessary spend and eliminates ongoing exposure.

## Reproduction and provenance

The report's aggregate numbers come from the frozen database at:

`evidence/final-2026-07-31/frozen/trap-house.db`

The daily summary is:

`digests/2026-07-31.md`

The final host state is:

`evidence/final-2026-07-31/frozen/host-inventory.txt`

The remote and local hash records are:

`evidence/final-2026-07-31/frozen/REMOTE-SHA256SUMS`

`evidence/final-2026-07-31/frozen/LOCAL-SHA256SUMS`

To reproduce the summary against a running deployment, use:

```text
bash scripts/digest.sh
```

The production server is intentionally offline, so the command will only work after a deliberate redeployment and new collection window.
