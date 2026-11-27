<p align="center"><img src="assets/netrik-logo.svg" width="96" alt="Netrik logo"></p>

# Netrik

Netrik is an evidence-driven network reconnaissance assistant for local networks.

It uses Nmap as an observation engine — not an attack tool — and performs staged, protocol-aware enumeration without making assumptions, over-scanning, or hiding uncertainty.

Netrik is designed to **think before it scans**.

---

## What Netrik Is

Netrik performs **safe, explainable network enumeration** by:

- Discovering hosts using minimal, local-network techniques
- Escalating scans only when prior evidence justifies it
- Running protocol-specific enumeration instead of blanket scans
- Separating **observed facts** from **inferred conclusions**
- Reporting confidence levels and explicit limitations

Netrik does **not** attempt to replace Nmap.  
It acts as a reasoning layer on top of it.

---

## What Netrik Is NOT

Netrik will **never**:

- Exploit vulnerabilities
- Brute-force services
- Perform vulnerability scanning
- Claim full device discovery
- Pretend certainty where none exists
- Run aggressive scans by default

This is a reconnaissance assistant, not a hacking framework.

---

## Design Philosophy

Netrik is built around these principles:

- **Logic before aggression**
- **Evidence before escalation**
- **Protocol awareness**
- **Explainable decisions**
- **Honest uncertainty**

Silence does not mean “down”.  
Unknown does not mean “vulnerable”.

---

## Intended Use

Netrik is intended for:

- Learning and practicing responsible network reconnaissance
- Understanding how scan results should be interpreted
- Building disciplined enumeration habits
- Educational and defensive analysis on networks you own or are authorized to assess

---

## Status

Netrik is under active development.

The current focus is on:
- Clear scan staging
- Transparent decision-making
- Structured, honest reporting

Features will be added only if they align with the core philosophy.

---

## Disclaimer

Netrik must only be used on networks you own or have explicit permission to analyze.

The author assumes no responsibility for misuse.


---

## Netrik web interface

A browser-based layer on top of the Netrik engine: multi-source inventory, change detection, blind-spot reporting,
a topology view, a safe incident simulator, plain-language findings, verification and exports.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config.example.yaml config.yaml   # then set your own ranges and zones
sudo apt install nmap                  # if missing
./scripts/setup_nmap_caps.sh           # optional: raw-socket scans without running as root
python run.py                          # http://127.0.0.1:8000  (first visit creates the admin account)
```

- Edit `config.yaml` for authorised ranges, zones and the intended access policy (restart afterwards).
- Settings has a clearly marked **demo network** for rehearsals or as a fallback; remove it with one click.
- A second network segment: run `python -m app.cli collect --target <range> --out bundle.json` there and import the file under Sources.
- Tests: `python -m unittest tests.test_app -v`

Evidence rules: every finding names its source and time, lists what is known and unknown, and an open port is never
called a vulnerability. Simulated results are always marked HYPOTHETICAL and never saved as findings.

### Policies and duplicate devices
- **Settings > Policies and rules:** add restricted websites, zone-to-zone rules and forbidden ports. Findings are raised from web/DNS logs
  (Sources), the optional DNS monitor, or scans. "Test a rule" records a clearly labelled test event for rehearsals.
- **Devices > Duplicates:** Netrik merges devices automatically only on reliable identifiers (same hardware MAC, same IP with a MAC,
  same specific hostname). Anything uncertain is listed for you to decide, and every merge is logged.
