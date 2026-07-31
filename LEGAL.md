# Trap House: Legal and Privacy Posture

This document records the project's design boundaries. It is not legal advice. A
real deployment should be reviewed against the operator's jurisdiction, hosting
provider terms, privacy obligations, and incident response policy.

## Jurisdiction

The project was operated from Norway under the Norwegian Penal Code
(Straffeloven). The official English translation identifies section 204 as
intrusion into a computer system and section 205 as violation of the right to
private communication:

https://lovdata.no/dokument/NLE/lov/2005-05-20-28

The collection was conducted on infrastructure controlled by the operator. The
VPS is now powered off and the evidence is frozen locally.

## What This System Does

- Deploys decoy services on infrastructure controlled by the operator
- Records unsolicited interactions for security monitoring and research
- Delays attackers through a tarpit and deception layers
- Maps observed behavior to the MITRE ATT&CK framework
- Keeps attacker-facing code in an emulated environment

## What This System Does Not Do

- It does not deploy malware against attackers
- It does not scan or probe attacker-controlled systems
- It does not execute attacker binaries
- It does not access attacker data or systems
- It does not perform hack-back or any other offensive action

The phrase "active antagonism" is therefore implemented only as defensive
deception, detection, and delay. No action touches the attacker's infrastructure.

## Canary and External Network Behavior

The current repository does not send canary events to an external canary service.
When `ENABLE_CANARYTOKENS=true`, the deception service changes the local event
mode from `would_trigger_canary` to `live`, but the current implementation still
records the event locally. `CANARY_EMAIL_DOMAIN` only changes the domain used in
fake dataset email addresses.

If an operator adds a real third-party webhook, that change requires a separate
privacy, consent, retention, and egress review. The egress firewall is designed
to make new public destinations explicit.

## Privacy and Retention

Source IP addresses and user-agent strings can constitute personal data under
GDPR and Norwegian data protection law. They must be handled as personal data,
not dismissed as anonymous operational metadata. Operators should document a
purpose, lawful basis, access controls, retention period, and data subject
handling process before deploying a live sensor.

The repository's retention controls are:

- JSONL logs are intended to be retained for 90 days by `deploy/prune-data.sh`
- SQLite event data is intended to be retained for 180 days by that script
- Docker `json-file` logs are capped at 10 MB per file and 3 files per container
- The final collection was closed, the VPS was powered off, and the frozen
  evidence is stored outside version control

## Production Security Boundary

The historical production layout exposed only ports 22, 2222, 2223, and 80.
Grafana and the custom frontend were bound to loopback and accessed through an
SSH tunnel. Host hardening used a firewall, fail2ban, unattended security
updates, key-only SSH, and an explicit honeypot egress policy.

The deployment scripts remain as historical reference material. They are not a
claim that the sensor is currently running.
