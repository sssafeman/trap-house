# Trap House: Results

Findings from the live deployment. The honeypot has been internet-facing on a VPS since 2026-06-30, collecting real attacker traffic against the Cowrie SSH honeypot, the Endlessh tarpit, and the deception web app.

> Data window: 2026-06-30 to 2026-07-08 (9 days). Figures below exclude the operator's own test traffic and the internal Docker gateway address.

## Volume

| Metric | Value |
|--------|-------|
| Total events captured | 31,788 |
| Unique attacker IP addresses | 416 |
| Distinct sessions | 6,886 |
| MITRE ATT&CK techniques observed | 11 |
| Events in last 24h | 3,534 |
| Events today (2026-07-08) | 998 |

Traffic breaks down as Cowrie SSH (the large majority), the Endlessh tarpit, and a smaller set of interactions against the deception web app. Volume grew 8.8x over the four days from the first sample (3,620 events on 2026-07-04) to the figures above.

### Event type breakdown (DB query)

| Event type | Count |
|------------|-------|
| session_connect | 6,598 |
| session_disconnect | 6,597 |
| client_version | 6,327 |
| client_kex | 5,910 |
| auth_attempt | 5,678 |
| tarpit_connect | 211 |
| auth_success | 144 |
| proxy_data | 64 |
| proxy_request | 64 |
| unknown | 53 |
| file_upload | 48 |
| command_exec | 38 |

The connect/disconnect and client_version/kex pairs line up, which confirms session accounting is consistent. The 144 auth_success events (against 5,678 auth_attempts) put the overall brute-force success rate at roughly 2.5%. The sum of event types in the table above (31,732) is 56 less than the total events captured (31,788). The difference is events logged before the event-type classification was added to the pipeline.

## Most-observed MITRE ATT&CK techniques

| Technique | Name | Hits |
|-----------|------|------|
| T1595.001 | Active Scanning: Scanning IP Blocks | 6,809 |
| T1049 | System Network Connections Discovery | 5,910 |
| T1087 | Account Discovery | 5,881 |
| T1110.001 | Brute Force: Password Guessing | 5,678 |
| T1078 | Valid Accounts | 144 |
| T1021 | Remote Services | 128 |
| T1082 | System Information Discovery | 51 |
| T1105 | Ingress Tool Transfer | 50 |
| T1083 | File and Directory Discovery | 41 |
| T1059 | Command and Scripting Interpreter | 40 |
| T1071.001 | Application Layer Protocol: Web Protocols | 2 |

The distribution matches the expected opportunistic-attacker profile: mass scanning and credential guessing, followed by post-access discovery commands (`uname`, `whoami`, `ls`, reading `/etc/passwd`) once a weak password lands them in the Cowrie shell.

**Mapper artifacts to flag:** T1049 (5,910 hits) and T1087 (5,881 hits) are inflated by the MITRE mapper tagging pre-authentication events. T1049 maps to every `client_kex` event (5,910), and T1087 maps to nearly every `auth_attempt` event (5,678). In a real host, these techniques correspond to post-compromise commands like `netstat` or `cat /etc/passwd`, not to the act of connecting or attempting login. The counts are retained here for transparency about mapper output, but should not be interpreted as genuine discovery activity. The post-authentication techniques (T1082, T1105, T1083, T1059) are the reliable signal.

## Credential guessing

The usernames attackers tried most were `root`, `admin`, and `support`, which is consistent with the curated Cowrie `userdb` accepting the planted `admin` decoy plus common weak `root` passwords. Successful logins (T1078) lead attackers into the fake shell where the planted `/home/admin/.env` steers them toward the deception web app.

### Auth success breakdown (DB query)

144 successful logins total:

| Username | Successes | Distinct source IPs |
|----------|-----------|---------------------|
| root | 71 | 40 |
| admin | 36 | 11 |
| support | 31 | 3 |
| debian | 2 | 2 |
| other | 4 | not captured |

The four unattributed successes (144 total minus 140 shown) came from usernames outside the top four. The `support` account is notable: only 3 source IPs but 31 successes. A small number of attackers specifically targeted `support` and succeeded repeatedly, a real-world credential reuse pattern worth flagging.

## Case Study: Outlaw/RedTail Cryptomining Campaign

The most significant intrusion captured during this window was a complete Outlaw/RedTail cryptomining kill chain from a single source IP. This is the centerpiece finding because it shows the full lifecycle of a deliberate intrusion, not just opportunistic scanning.

### Attacker profile (DB query + session replay)

- Source IP: 130.12.180.51 (Saudi Arabia)
- First seen: 2026-06-30T07:05:52Z
- Last seen: 2026-07-07T22:23:44Z
- Events: 162
- Sessions: 18
- Risk score: 31.0
- MITRE techniques observed: 8
- Top username: root

### Threat intel corroboration (ThreatFox + VirusTotal)

ThreatFox confirms the delivered binaries are known Outlaw/RedTail malware:

- IOC 1820703: `redtail.x86_64`, malware family `elf.redtail`, confidence high (85%). Tags: elf, miner, Redtail, x86_64, xmrig. First seen 2026-06-01.
- IOC 1831959: `setup.sh`, malware family `elf.xmrig`. Tags: dota3, mdrfckr, miner, outlaw, ssh. Reported by nullblue67.
- The x86_64 binary scores 37/64 on VirusTotal (queried 2026-07-08).

### Kill chain (reconstructed from session replay and command_exec)

1. **T1110.001 Brute Force:** hammered `root`, succeeded (T1078). This attacker was one of 40 distinct IPs that successfully authenticated as root.
2. **T1082 System Information Discovery:** ran `uname -s -m` to fingerprint architecture.
3. **T1105 Ingress Tool Transfer:** uploaded 6 files via SFTP to Cowrie, repeated 8 times between 2026-07-04 and 2026-07-07.
4. **Persistence:** injected an SSH `authorized_keys` entry, then locked it with `chattr +ai` (immutable attribute). The key was labeled `rsa-key-20230629`, a known Outlaw signature.
5. **T1059 Execution:** ran `chmod +x clean.sh; sh clean.sh; rm -rf clean.sh; chmod +x setup.sh; sh setup.sh; rm -rf setup.sh; ...` then `setup.sh` executed the architecture-matched `redtail` binary.

### Uploaded files (sha256 verified, captured to local evidence/ dir)

| File | Size (bytes) | sha256 |
|------|--------------|--------|
| clean.sh | 1,269 | 197c74408e15bd1168105f564f96aace4fd4819961b724630bf5a6be4878daf8 |
| setup.sh | 1,951 | 783adb7ad6b16fe9818f3e6d48b937c3ca1994ef24e50865282eeedeab7e0d59 |
| redtail.arm7 | 1,299,516 | 3625d068896953595e75df328676a08bc071977ac1ff95d44b745bbcb7018c6f |
| redtail.arm8 | 1,560,860 | dbb7ebb960dc0d5a480f97ddde3a227a2d83fcaca7d37ae672e6a0a6785631e9 |
| redtail.i686 | 1,748,196 | 048e374baac36d8cf68dd32e48313ef8eb517d647548b1bf5f26d2d0e2e3cdc7 |
| redtail.x86_64 | 1,880,264 | 59c29436755b0778e968d49feeae20ed65f5fa5e35f9f7965b8ed93420db91e5 |

### Script analysis (from captured binaries)

`clean.sh` is a competitor-killer (1,269 bytes):

- Stops and disables any existing `c3pool_miner` systemd service.
- Scrubs cron entries containing `wget`, `curl`, `/dev/tcp`, `/tmp`, `.sh`, `nc`, `bash -i`, `base64` from every cron location (hourly, daily, weekly, monthly, anacrontab, user crontabs).
- Wipes `/tmp`, `/var/tmp`, `/dev/shm`.
- Cleans `.bashrc`, `.bash_profile`, `.profile`.
- Kills processes named `systemtd`, `/bin/-bash`, `/usr/bin/.sh` (names that mimic legitimate system binaries).

`setup.sh` is the dropper (1,951 bytes):

- Generates a random filename to avoid detection.
- Detects architecture (x86_64, i686, arm8, arm7) via `uname -mp`.
- Finds a writable, executable directory outside `noexec` mounts.
- Copies the matching `redtail` binary there with a random name.
- Runs it with `./$FILENAME ssh`. The `ssh` argument is the RedTail C2 mode, meaning the binary reaches out to its controller over SSH.
- Deletes the `redtail.*` files to clean up.

The honeypot logged the commands and accepted the SFTP uploads but did not execute the binaries, which is the correct behavior for a deception sensor.

## Secondary Campaign: Bash Dropper Stagers

Two IPs ran an identical, more modern dropper pattern. These are a separate actor from the Outlaw/RedTail campaign above, not the same operator.

- 39.106.160.3 on 2026-07-04, pulling from 8.219.7.59:6859.
- 47.109.80.198 on 2026-07-08, pulling from 220.180.99.71:60105.

Pattern (identical in both, reconstructed from command_exec):

1. `echo 1 > /dev/null && cat /bin/echo` (shell fingerprinting, testing whether the fake shell behaves correctly).
2. `nohup` with a `curl`/`wget`/`/dev/tcp` fallback chain to download a `linux` binary to `/tmp`. The `/dev/tcp` fallback works even when `curl` and `wget` are absent, using the bash built-in TCP.
3. `head -c 3716336 > /tmp/...` writes exactly 3,716,336 bytes, a fixed-size payload.
4. Executes the binary with a large base64 blob as an argument (an encrypted C2 config or session key).
5. `echo 123456 > /tmp/.opass` drops a marker file.

These map to T1105 Ingress Tool Transfer and T1059 Command and Scripting Interpreter. The honeypot logged the commands but did not execute them, which is the correct behavior.

## Proxy Abuse

Three IPs tried to relay traffic through the honeypot. These map to T1090 (Proxy), which the MITRE mapper does not tag yet. Noting the gap here so it can be closed in a future mapper update.

- 45.148.10.121: STUN/TURN relay to 141.101.90.1:3478 (Cloudflare), 30 events over several days. Attempting to use the box as a proxy for VoIP or NAT traversal.
- 176.53.159.196: DNS proxy to 1.1.1.1:53, 22 events. Using it as an open DNS resolver, possibly for DNS amplification.
- 64.89.162.38: HTTP proxy to itself on port 80. Checking whether it is an open proxy.

## Dominant noise source

101.201.76.235 (Alibaba Cloud, China): 21,302 events, 67% of all traffic. A dumb brute-forcer. 4,259 auth_attempt events, all username `root`, never succeeded, never uploaded, never ran a command. It hammers `root` with a password list and disconnects every 2 seconds. It is useful for the brute force volume metric, not for TTPs. It is included here as the contrast between automated noise and the deliberate intrusion in the case study above.

## Notable attacker behavior

Several source IPs ran full discovery sequences after logging in: enumerating the filesystem, reading the decoy `.env`, and probing network configuration. These are the sessions most worth reviewing in the SOC dashboard's session replay, which reconstructs each attacker's path through the deception layers.

## Limitations and Defensive Takeaways

### Honeypot limitations

- Cowrie is a low-interaction SSH honeypot. It does not execute uploaded binaries, so the kill chain reconstruction stops at the execution step. Outbound C2 traffic, lateral movement, and actual mining behavior are not captured.
- The Endlessh tarpit only logs connection attempts. No attacker interaction beyond the TCP handshake is recorded.
- The deception web app is static and received minimal interaction during this window. No significant web-based attacks were observed.
- The MITRE mapper does not tag T1090 (Proxy) events. This is a known gap to address in a future mapper update.
- T1049 and T1087 counts are mapper artifacts from pre-authentication events, not genuine post-compromise discovery. See the note in the MITRE techniques section.

### Defensive takeaways

- The Outlaw/RedTail campaign demonstrates a repeatable pattern: brute force root, upload architecture-specific binaries, inject an SSH key with `chattr +ai`, and execute a dropper. Blue teams should alert on `authorized_keys` files with immutable attributes and on processes named `systemtd` or `/bin/-bash`.
- The `support` account credential reuse (31 successes from only 3 IPs) suggests attackers share password lists targeting service accounts. Organizations should treat any account with a common weak password as a high-risk target.
- The bash dropper stagers use a `/dev/tcp` fallback, which bypasses traditional `curl`/`wget` detection. Network monitoring should look for outbound connections on arbitrary ports from shell processes.
- Proxy abuse attempts (STUN/TURN, DNS, HTTP) indicate the honeypot IP is being scanned for open relay capabilities. Blocking these at the network edge is recommended.

## Dashboard

The custom SOC dashboard visualizes all of the above: a Leaflet attack map of source-IP geolocations, a MITRE ATT&CK heatmap, per-session replay, and a filterable event timeline. Reach it over the SSH tunnel at `http://localhost:8001`.

> Note: screenshots of the attack map, the MITRE heatmap, the Outlaw session replay (130.12.180.51), and top attacker profiles should be added to `docs/img/` to make this section self-contained for readers who are not running the stack.

## Reproducing these numbers

The `scripts/digest.sh` cron job writes a dated markdown summary (totals, unique IPs, 24h deltas, top attackers by risk score, technique counts, recent events) to `digests/`. This report is a curated snapshot of that data. The event-type and technique counts above come from direct SQLite queries against the intel store at `data/db/trap-house.db`.