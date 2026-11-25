# ChargeShield: Securing EV Charging Infrastructure

A research-style article (Springer LNCS format, written in LaTeX for Overleaf) that **verifies security problems in Electric Vehicle (EV) charging infrastructure** and shows **how to overcome the limitations of existing market security tools**.

## Why EV charging?

A modern charging station is a networked computer. It talks to the car (ISO 15118), to a cloud management system (OCPP), to payment back-ends, and to the power grid. A weakness in any of these links can lead to energy theft, billing fraud, stolen payment data, denial of service, or even coordinated attacks that destabilise the grid.

## What the article covers

| Section | Content |
|---|---|
| **Introduction** | The EV charging ecosystem, the CIA triad, and the contributions |
| **Verifying the problems** | Nine problems (P1–P9) mapped to the attack phases: reconnaissance → scanning → gaining access → maintaining access → covering tracks |
| **Literature review** | Published research on OCPP attacks, physical-layer attacks (PLC eavesdropping, Brokenwire), IDS and cryptography |
| **Existing tools and their gaps** | Nmap, Shodan, Nessus/OpenVAS, Wireshark, Snort/Suricata, Zeek and SIEMs, plus why they are *protocol-blind* for EV charging |
| **Technology used: ChargeShield** | A four-layer defence framework (below) |
| **Comparison and evaluation** | Coverage table against existing tools, a testbed evaluation method, and limitations |

## ChargeShield: proposed framework

1. **Cryptographic identity:** ECC-based mutual TLS 1.3, V2G public-key infrastructure, OCSP revocation checks and signed firmware with secure boot.
2. **Protocol-aware deep packet inspection:** an OCPP / ISO 15118 parser with schema checks, state-machine checks and physics-based plausibility checks on meter values.
3. **ML anomaly detection:** an Isolation Forest and an autoencoder on charging telemetry, plus fleet-level correlation.
4. **Zero-trust policy engine:** per-request authorisation, micro-segmentation, and two-person approval for high-impact commands.

## Files

- `main.tex`: article source (pdfLaTeX, `llncs` document class)
- `references.bib`: bibliography of 23 references (`splncs04` style)

## Build / open in Overleaf

1. In Overleaf, choose **New Project → Import from GitHub** and select this repository, or upload `main.tex` and `references.bib`.
2. Set the compiler to **pdfLaTeX** and click **Recompile**.

Local build:

```bash
pdflatex main && bibtex main && pdflatex main && pdflatex main
```

## Keywords

EV charging security · OCPP · ISO 15118 · Public-key cryptography · Network reconnaissance · Intrusion detection · Zero trust
