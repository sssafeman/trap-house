# Trap House Detection Engineering Pack Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task by task.

**Goal:** Convert Trap House telemetry into a small, tested detection pack that demonstrates how collected events become actionable SOC alerts.

**Architecture:** Keep Trap House frozen and untouched as the evidence archive. Add a separate detection pack containing Sigma rules, Splunk searches, compact synthetic fixtures, validation tests, and an analyst guide. Use real Trap House event names and field meanings, but do not export raw IP addresses, credentials, or the full evidence database into the detection fixtures.

**Tech Stack:** Sigma YAML, Splunk SPL, Python unittest, PyYAML, SQLite read-only queries, MITRE ATT&CK references.

---

## Scope and acceptance criteria

The first version should contain five detections:

1. SSH password spraying against multiple decoy accounts.
2. Successful decoy login followed by command execution.
3. Successful decoy login followed by file upload.
4. Webshell upload followed by command execution.
5. Cross-layer activity where one session reaches multiple deception services.

Every detection must include:

- A stable rule identifier.
- A clear title and severity.
- Source event fields.
- A short analyst explanation.
- A MITRE ATT&CK technique where justified.
- One positive fixture.
- One negative fixture or suppression case.
- A documented false-positive consideration.

The pack is complete when all five rules validate, all fixtures test successfully, the README links to the pack, and the detection guide explains how to port the logic to a real SIEM.

## Task 1: Define the detection event contract

**Objective:** Document the normalized fields that detection rules may consume.

**Files:**
- Create: `detections/README.md`
- Modify: `EVENT_SCHEMA.md`
- Test: `tests/test_detections.py`

**Steps:**

1. List the event types and fields needed by the five detections.
2. Document session identity, timestamps, source service, source IP handling, usernames, event type, upload metadata, and MITRE fields.
3. State that fixtures must use synthetic or anonymized source values.
4. Add a test that loads the contract metadata and confirms every required field has a description.
5. Run:

```bash
python3 -m unittest tests.test_detections -v
```

**Expected:** The new test initially fails until the contract metadata exists, then passes.

## Task 2: Create safe synthetic fixtures

**Objective:** Provide compact positive and negative event sequences without copying sensitive historical data.

**Files:**
- Create: `detections/fixtures/password-spray.json`
- Create: `detections/fixtures/login-command.json`
- Create: `detections/fixtures/login-upload.json`
- Create: `detections/fixtures/webshell-upload-exec.json`
- Create: `detections/fixtures/cross-layer-session.json`
- Create: `detections/fixtures/negative-benign-session.json`
- Test: `tests/test_detections.py`

**Steps:**

1. Use reserved documentation IP ranges or stable placeholders such as `198.51.100.10`.
2. Use clearly marked decoy usernames and synthetic filenames.
3. Represent each fixture as a short event sequence with timestamps and one session ID.
4. Add a loader test that rejects real-looking credentials, private key headers, and unapproved source IP values.
5. Add tests confirming every fixture has at least one event and a declared expected result.
6. Run the detection tests.

**Expected:** Fixtures are self-contained, reproducible, and contain no historical PII or credentials.

## Task 3: Implement five Sigma rules

**Objective:** Express the detections in a portable SIEM rule format.

**Files:**
- Create: `detections/sigma/thp-ssh-password-spray.yml`
- Create: `detections/sigma/thp-login-command-chain.yml`
- Create: `detections/sigma/thp-login-upload-chain.yml`
- Create: `detections/sigma/thp-webshell-upload-exec.yml`
- Create: `detections/sigma/thp-cross-layer-session.yml`
- Test: `tests/test_detections.py`

**Steps:**

1. Give each rule a stable identifier, title, status, level, logsource, detection section, tags, and analyst note.
2. Keep event matching based on normalized fields rather than raw message text.
3. Use correlation logic or documented grouping requirements for sequences.
4. Map only techniques supported by the actual event sequence.
5. Add tests that parse every YAML file and verify required Sigma keys.
6. Add tests that associate each rule with its positive fixture.

**Expected:** Five valid, reviewable Sigma rules with no hardcoded secrets or raw historical IP addresses.

## Task 4: Add Splunk searches and field mapping

**Objective:** Make the same detections immediately useful to a Splunk user.

**Files:**
- Create: `detections/splunk/thp-ssh-password-spray.spl`
- Create: `detections/splunk/thp-login-command-chain.spl`
- Create: `detections/splunk/thp-login-upload-chain.spl`
- Create: `detections/splunk/thp-webshell-upload-exec.spl`
- Create: `detections/splunk/thp-cross-layer-session.spl`
- Modify: `detections/README.md`
- Test: `tests/test_detections.py`

**Steps:**

1. Use `index`, `sourcetype`, and field names as configurable placeholders.
2. Document the expected input mapping from Trap House JSONL to Splunk fields.
3. Keep searches readable and explain each correlation window.
4. Add a test that checks every search includes a rule identifier comment and a session or source grouping field.
5. Run all detection tests.

**Expected:** A Splunk analyst can adapt each search without reverse engineering the repository.

## Task 5: Build the detection validation harness

**Objective:** Prove that positive sequences alert and negative sequences do not.

**Files:**
- Modify: `tests/test_detections.py`
- Create: `detections/validate.py`
- Modify: `Makefile`

**Steps:**

1. Implement small deterministic evaluators for the five sequence patterns.
2. Keep the evaluator independent from the production log shipper.
3. Test positive and negative fixtures separately.
4. Add the detection tests to the existing `make test` target.
5. Run:

```bash
make test
```

**Expected:** Existing Trap House checks and detection checks pass together.

## Task 6: Write the analyst guide

**Objective:** Explain how the detections would be used in a real SOC.

**Files:**
- Create: `docs/DETECTION_ENGINEERING.md`
- Modify: `README.md`

**Steps:**

1. Explain the difference between telemetry collection, enrichment, and detection.
2. Show one complete investigation path from alert to session replay.
3. Document expected false positives and tuning options.
4. Explain how the rules could be translated to Splunk, Elastic, or another SIEM.
5. Add a short scaling note covering centralized ingestion, queues, and a server database for multiple honeypots.
6. Link the guide and detection pack from the README.
7. Confirm all claims distinguish the frozen historical archive from future live collection.

**Expected:** A hiring manager can understand the defensive value without reading every source file.

## Task 7: Final review and portfolio packaging

**Objective:** Validate the pack and prepare a concise portfolio section.

**Files:**
- Modify: `README.md`
- Modify: `RESULTS.md` only if the detection results are derived from the frozen data and clearly labeled.

**Steps:**

1. Run YAML parsing, detection tests, `make test`, and the repository secret scan.
2. Review every fixture for PII, credentials, private addresses, and misleading claims.
3. Add a README section titled `Detection Engineering Extension` with links to the rules and guide.
4. Add a short portfolio paragraph describing five detections built from observed attacker behavior.
5. Run `git diff --check`.
6. Commit the pack separately from the frozen evidence artifacts.

**Expected:** The original Trap House evidence remains unchanged, while the new pack demonstrates actionable SOC detection engineering.

## Out of scope for version one

- Re-deploying the VPS.
- Modifying the frozen database.
- Adding a new production SIEM.
- Building a general-purpose rule engine.
- Exporting raw historical IP addresses or credentials.
- Claiming that the rules are production-ready without deployment and tuning data.
