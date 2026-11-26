"""ChargeShield demo.

Simulates one day of OCPP traffic from a fleet of chargers, injects attacks,
and runs the ChargeShield layers against it. A protocol-unaware baseline
(syntax checks only, like a generic IDS) is run on the same traffic for
comparison.

Usage:  python demo.py [--chargers 20] [--seed 7]
All traffic is synthetic; the numbers show how the layers behave on this
simulation and are not measurements from real chargers.
"""
import argparse
from collections import Counter, defaultdict

from chargeshield.simulator import FleetSimulator, L2_ATTACKS, L3_ATTACKS
from chargeshield.inspector import ProtocolInspector, baseline_signature_check
from chargeshield.detector import AnomalyDetector, window_features, fleet_correlation, FEATURES
from chargeshield.identity import ecdhe_demo, firmware_demo


def metrics(tp, fp, tn, fn):
    recall = tp / (tp + fn) if tp + fn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "Recall": recall, "Precision": precision, "FPR": fpr, "F1": f1}


def print_metrics(name, m):
    print(f"  {name:<34} TP={m['TP']:<4} FP={m['FP']:<4} TN={m['TN']:<6} FN={m['FN']:<4} "
          f"Recall={m['Recall']:.2f}  Precision={m['Precision']:.2f}  "
          f"FPR={m['FPR']:.4f}  F1={m['F1']:.2f}")


def header(title):
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--chargers", type=int, default=20)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    # ------------------------------------------------------------------
    header("LAYER 1 - Cryptographic identity")
    k1, k2 = ecdhe_demo()
    print(f"  ECDHE (P-256): charger key = {k1.hex()[:32]}...")
    print(f"                 server  key = {k2.hex()[:32]}...")
    print(f"  Both sides derived the same secret K = abG: {k1 == k2}")
    fw = firmware_demo()
    print(f"  Firmware ({fw['firmware_bytes']} bytes) signed with ECDSA-SHA256 "
          f"({fw['signature_bytes']}-byte signature)")
    print(f"  Genuine firmware accepted by bootloader:  {fw['genuine_accepted']}")
    print(f"  Firmware with ONE flipped bit accepted:   {fw['tampered_accepted']}")

    # ------------------------------------------------------------------
    header("Generating traffic")
    train = FleetSimulator(args.chargers, seed=args.seed + 1000).generate_normal()
    test = FleetSimulator(args.chargers, seed=args.seed).generate_normal().inject_attacks()
    train_events, events = train.sorted_events(), test.sorted_events()
    labels = Counter(e.label for e in events)
    print(f"  Training day (normal only): {len(train_events)} messages")
    print(f"  Test day: {len(events)} messages from {args.chargers} chargers")
    for lab, n in sorted(labels.items()):
        print(f"    {lab:<20} {n}")

    # ------------------------------------------------------------------
    header("LAYER 2 - Protocol-aware inspection (per message)")
    inspector = ProtocolInspector(test.chargers)
    cs_flag, base_flag, examples = {}, {}, defaultdict(list)
    for i, e in enumerate(events):
        v = inspector.inspect(e)
        cs_flag[i] = v.decision != "FORWARD"
        base_flag[i] = baseline_signature_check(e)
        if cs_flag[i] and len(examples[e.label]) < 2:
            examples[e.label].append(f"[{v.decision}] {e.charger}: {v.reason}")
    for lab in L2_ATTACKS + ["normal"]:
        for line in examples.get(lab, []):
            print(f"  {lab:<17} {line}")

    def msg_metrics(flags):
        tp = sum(1 for i, e in enumerate(events) if e.label in L2_ATTACKS and flags[i])
        fn = sum(1 for i, e in enumerate(events) if e.label in L2_ATTACKS and not flags[i])
        fp = sum(1 for i, e in enumerate(events) if e.label not in L2_ATTACKS and flags[i])
        tn = sum(1 for i, e in enumerate(events) if e.label not in L2_ATTACKS and not flags[i])
        return metrics(tp, fp, tn, fn)
    print()
    print_metrics("Baseline (syntax-only IDS)", msg_metrics(base_flag))
    print_metrics("ChargeShield Layer 2", msg_metrics(cs_flag))

    # ------------------------------------------------------------------
    header("LAYER 3 - Anomaly detection on (charger, hour) windows")
    _, X_train = window_features(train_events, train.valid_tags)
    keys, X_test = window_features(events, test.valid_tags)
    det = AnomalyDetector().fit(X_train)
    flagged, reasons = det.predict(X_test)
    scores = det.anomaly_score(X_test)

    window_labels = defaultdict(set)
    for e in events:
        if e.label in L3_ATTACKS:
            window_labels[(e.charger, int(e.t // 3600))].add(e.label)
    y = [bool(window_labels.get(k)) for k in keys]
    tp = sum(1 for yi, fi in zip(y, flagged) if yi and fi)
    fn = sum(1 for yi, fi in zip(y, flagged) if yi and not fi)
    fp = sum(1 for yi, fi in zip(y, flagged) if not yi and fi)
    tn = sum(1 for yi, fi in zip(y, flagged) if not yi and not fi)
    print(f"  Trained on {len(X_train)} normal windows, features: {', '.join(FEATURES)}")
    print(f"  Flagged windows (most anomalous first):")
    order = sorted(range(len(keys)), key=lambda j: -scores[j])
    for j in order:
        if flagged[j]:
            cp, h = keys[j]
            truth = ", ".join(sorted(window_labels.get(keys[j], []))) or "normal (false alarm)"
            print(f"    {cp} hour {h:>2}  IF-score={scores[j]:.3f}  truth: {truth}")
            print(f"        why: {reasons[j]}")
    print()
    print_metrics("ChargeShield Layer 3 (windows)", metrics(tp, fp, tn, fn))

    # ------------------------------------------------------------------
    header("FLEET CORRELATION - coordinated SetChargingProfile")
    alerts = fleet_correlation(events, args.chargers)
    for a in alerts:
        print(f"  ALERT: {len(a['chargers'])} chargers re-profiled between "
              f"t={a['start']:.0f}s and t={a['end']:.0f}s -> possible grid attack")
    if not alerts:
        print("  no fleet alerts")

    # ------------------------------------------------------------------
    header("LAYER 4 - Policy responses (zero trust)")
    # graded response: a strong, explainable signal (a feature far outside its
    # normal range) justifies quarantine; a weak signal (Isolation Forest only)
    # only raises an alert, so a false alarm does not lock drivers out.
    for j in order:
        if not flagged[j]:
            continue
        cp, h = keys[j]
        if "z=" in reasons[j]:
            print(f"  {cp} hour {h:>2}: HIGH risk -> quarantine, revoke certificate, local-only mode")
        else:
            print(f"  {cp} hour {h:>2}: MEDIUM risk -> alert operator for review, keep charging")
    for a in alerts:
        print(f"  Fleet: hold further SetChargingProfile commands, require two-person approval")

    # ------------------------------------------------------------------
    header("SUMMARY - which attacks were detected")
    print(f"  {'Attack':<20}{'Injected':>9}{'Baseline':>10}{'ChargeShield':>14}   Layer")
    for lab in L2_ATTACKS:
        idx = [i for i, e in enumerate(events) if e.label == lab]
        print(f"  {lab:<20}{len(idx):>9}{sum(base_flag[i] for i in idx):>10}"
              f"{sum(cs_flag[i] for i in idx):>14}   2 (inspection)")
    for lab in L3_ATTACKS:
        inst = [(a["charger"], a["hour"]) for a in test.attack_instances if a["type"] == lab]
        hit = sum(1 for k in inst if flagged[keys.index(k)])
        print(f"  {lab:<20}{len(inst):>9}{0:>10}{hit:>14}   3 (anomaly)")
    fa = [a for a in test.attack_instances if a["type"] == "fleet_load_attack"]
    hit = sum(1 for a in fa if any(al["end"] >= a["start"] and al["start"] <= a["end"] + 300
                                   for al in alerts))
    print(f"  {'fleet_load_attack':<20}{len(fa):>9}{0:>10}{hit:>14}   fleet correlation")
    print("\n  Note: all traffic is synthetic. The baseline is a simplified stand-in for a")
    print("  protocol-unaware IDS, not a measurement of a real product.")


if __name__ == "__main__":
    main()
