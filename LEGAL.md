# Trap House: Legal Framework

## Jurisdiction
Norway. Norwegian Penal Code (Straffeloven). EU Directive 2013/40/EU via EEA agreement.

## What This System Does (Legal)
- Deploys decoy services on owned infrastructure
- Logs attacker interactions for threat intelligence
- Delays attackers through tarpits and deception layers
- Maps attacker behavior to MITRE ATT&CK framework
- Reports attacker IPs to blocklists (optional)

## What This System Does NOT Do (Legal Boundary)
- Does NOT deploy malware against attackers
- Does NOT scan or probe attacker machines
- Does NOT execute code on attacker systems
- Does NOT access attacker data or systems
- Does NOT perform any offensive action regardless of provocation

## Relevant Norwegian Law

Strafeloven section 204: Criminalizes creating, storing, or spreading programs designed for unauthorized access. This system does not create such programs.

Strafeloven section 205: Criminalizes unauthorized access to others' systems. This system does not access attacker systems.

Strafeloven section 18 (nødværge/self-defense): Covers imminent physical threats. Does not extend to cyber hack-back. No court has accepted cyber hack-back as self-defense.

## "Active Antagonism" Reframed
The original requirement used the phrase "active antagonism." In implementation, this means:
- Defensive deception: presenting fake services and credentials to mislead attackers
- Detection: logging and analyzing all attacker behavior
- Delay: using tarpits and maze logic to waste attacker time

It does NOT mean:
- Degrading attacker systems
- Scanning attacker machines
- Deploying counter-malware
- Any action that touches the attacker's infrastructure

## Canarytokens
Canarytokens.org integration sends attacker behavior data (IP, user agent) to a third-party service (Thinkst Canary). This is optional and toggleable via environment variable ENABLE_CANARYTOKENS=true/false.

A local canary logger is provided as fallback. It logs canary trigger events locally without contacting any external service.

## Data Retention
- Logs retained for 90 days maximum
- SQLite database retained for 180 days maximum
- Automated cleanup via log-shipper (configurable)
- No PII stored beyond attacker IP and user agent (which are operational data, not personal data under GDPR for security purposes)

## Production Deployment
When deployed on Hetzner VPS:
- Only ports 22, 2222, 2223, and 80 exposed externally
- Grafana and frontend accessible only via SSH tunnel
- Host hardened: firewall, fail2ban, unattended upgrades
- No outbound traffic from honeypot containers except canarytokens (toggleable)