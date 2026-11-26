# ChargeShield prototype

A small, runnable proof of concept of the layers described in the paper. It runs **offline on synthetic OCPP traffic**; there are no real chargers or network connections involved.

## Run it

```bash
cd prototype
pip install -r requirements.txt
python demo.py              # default: 20 chargers, seed 7
python demo.py --seed 3     # a different simulated day
```

## What it does

| File | Paper section | What it shows |
|---|---|---|
| `chargeshield/simulator.py` | Experimental design | Generates a day of OCPP messages (`Heartbeat`, `Authorize`, `StartTransaction`, `MeterValues`, ...) for a fleet of chargers, then injects 8 attack types with ground-truth labels |
| `chargeshield/identity.py` | Layer 1 | ECDHE on P-256 (both sides derive the same secret K = abG); ECDSA-SHA256 signed firmware, where flipping one bit makes the bootloader reject it |
| `chargeshield/inspector.py` | Layer 2, Algorithm 1 | Schema, state-machine and physics plausibility checks per message, plus a **syntax-only baseline** that stands in for a protocol-unaware IDS |
| `chargeshield/detector.py` | Layer 3 + fleet correlation | Isolation Forest plus a robust z-score check on (charger, hour) windows, trained on normal traffic only; detects many chargers re-profiled at once |
| `demo.py` | Evaluation | Runs everything and prints Recall, Precision, FPR and F1, plus a per-attack comparison with the baseline |

## Attacks simulated

| Attack | Problem (paper) | Caught by |
|---|---|---|
| malformed / injection-style messages | P3 | Layer 2 schema check (the baseline also catches these) |
| `MeterValues` for a transaction that never started (spoofed charger) | P3 | Layer 2 state check |
| meter going backwards (billing fraud) | P4 | Layer 2 plausibility |
| physically impossible energy jump | P4 | Layer 2 plausibility |
| RFID card brute force | P2 | Layer 3 |
| message flood | P8 / DoS | Layer 3 |
| configuration tampering | P5 / P6 | Layer 3 |
| fleet-wide `SetChargingProfile` (grid attack) | P8 | Fleet correlation |

## Example result (seed 7)

```
Baseline (syntax-only IDS)   Recall=0.25  Precision=1.00  FPR=0.0000
ChargeShield Layer 2         Recall=1.00  Precision=1.00  FPR=0.0000
ChargeShield Layer 3         Recall=1.00  Precision=0.86  FPR=0.0021   (1 false alarm)
Fleet correlation            15 chargers re-profiled within ~2 min -> alert
```

The baseline only catches the 5 malformed messages. The 15 forged but well-formed messages (spoofed transactions, meter rollback, impossible power) pass it, and only the protocol-aware layer catches them.

## Design note found while building

The Isolation Forest alone **missed** obvious attacks such as 400 heartbeats in an hour instead of the normal 12. Its random splits only cover the range seen in training, so a value far outside that range is not isolated faster than the most extreme normal window. Adding a robust z-score check (median and MAD per feature) fixed this. The two detectors complement each other: one finds unusual combinations inside the normal range, the other finds values far outside it.

## Limitations

- The traffic is synthetic and the attacks are simple, so the numbers show how the layers *behave*. They are not real-world performance figures.
- The baseline is a simplified stand-in for a generic IDS, not a measurement of Snort or Suricata.
- The OCPP message set is a simplified subset (for example, `StartTransaction` carries its own `transactionId`).
- It runs offline on recorded events; a real deployment would run Layer 2 inside a WebSocket/TLS proxy in front of a CSMS such as SteVe or CitrineOS.
