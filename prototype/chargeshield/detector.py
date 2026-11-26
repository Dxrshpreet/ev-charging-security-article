"""Layer 3: unsupervised anomaly detection, plus fleet-level correlation.

Each (charger, hour) window is turned into a feature vector of message counts.
An Isolation Forest is trained on normal traffic only, so no labelled attack
data is needed. Windows that score as more anomalous than almost all of the
training windows are flagged.
"""
import json
import numpy as np
from sklearn.ensemble import IsolationForest

FEATURES = ["messages", "heartbeats", "authorize", "unknown_id_tags",
            "transactions", "meter_values", "config_changes", "charging_profiles"]


def window_features(events, valid_tags, window_s=3600):
    rows = {}
    for e in events:
        key = (e.charger, int(e.t // window_s))
        f = rows.setdefault(key, dict.fromkeys(FEATURES, 0))
        try:
            msg = json.loads(e.raw)
            action = msg[2]
            payload = msg[3] if isinstance(msg[3], dict) else {}
        except Exception:
            action, payload = "INVALID", {}
        f["messages"] += 1
        if action == "Heartbeat":
            f["heartbeats"] += 1
        elif action == "Authorize":
            f["authorize"] += 1
            if payload.get("idTag") not in valid_tags:   # the CSMS knows its card list
                f["unknown_id_tags"] += 1
        elif action == "StartTransaction":
            f["transactions"] += 1
        elif action == "MeterValues":
            f["meter_values"] += 1
        elif action == "ChangeConfiguration":
            f["config_changes"] += 1
        elif action == "SetChargingProfile":
            f["charging_profiles"] += 1
    keys = sorted(rows)
    X = np.array([[rows[k][n] for n in FEATURES] for k in keys], dtype=float)
    return keys, X


class AnomalyDetector:
    """Two unsupervised detectors trained on normal traffic only.

    * Isolation Forest finds unusual COMBINATIONS of features inside the range
      seen during training.
    * Isolation Forest cannot extrapolate: its random splits only cover the
      training range, so a value far beyond it (400 heartbeats instead of 12)
      is not isolated faster than the most extreme normal window. A robust
      z-score check (median / MAD per feature) covers exactly that case.
    A window is flagged if either detector fires.
    """

    def __init__(self, threshold_percentile=0.5, z_threshold=6.0, seed=0):
        self.model = IsolationForest(n_estimators=200, random_state=seed)
        self.threshold_percentile = threshold_percentile
        self.z_threshold = z_threshold

    def fit(self, X_train):
        self.model.fit(X_train)
        # score_samples: lower = more anomalous
        self.threshold = np.percentile(self.model.score_samples(X_train),
                                       self.threshold_percentile)
        self.median = np.median(X_train, axis=0)
        mad = np.median(np.abs(X_train - self.median), axis=0) * 1.4826
        self.scale = np.maximum(mad, 1.0)          # floor: counts move in steps of 1
        return self

    def anomaly_score(self, X):
        """Paper's score s(x) in (0, 1]; close to 1 means anomalous."""
        return -self.model.score_samples(X)

    def robust_z(self, X):
        return (X - self.median) / self.scale

    def predict(self, X):
        """Returns (flags, reasons) where reasons explains each flagged window."""
        if_flag = self.model.score_samples(X) < self.threshold
        z = self.robust_z(X)
        flags, reasons = [], []
        for i in range(len(X)):
            why = [f"{FEATURES[j]}={X[i, j]:.0f} (normal ~{self.median[j]:.0f}, z={z[i, j]:.0f})"
                   for j in range(X.shape[1]) if z[i, j] > self.z_threshold]
            if if_flag[i]:
                why.append("unusual feature combination (Isolation Forest)")
            flags.append(bool(why))
            reasons.append("; ".join(why))
        return np.array(flags), reasons


def fleet_correlation(events, fleet_size, window_s=300, min_fraction=0.3):
    """Alert when many different chargers receive SetChargingProfile within a
    short time: a sign of a coordinated attack on grid load."""
    cmds = sorted((e.t, e.charger) for e in events
                  if e.direction == "csms->cp" and '"SetChargingProfile"' in e.raw)
    needed = max(5, int(min_fraction * fleet_size))
    alerts, i, quiet_until = [], 0, float("-inf")
    for j, (t, _) in enumerate(cmds):
        while cmds[i][0] < t - window_s:
            i += 1
        distinct = {c for _, c in cmds[i:j + 1]}
        if len(distinct) >= needed and t > quiet_until:
            start = cmds[i][0]
            burst = {c for tt, c in cmds if start <= tt <= start + window_s}
            end = max(tt for tt, _ in cmds if start <= tt <= start + window_s)
            alerts.append({"start": start, "end": end, "chargers": sorted(burst)})
            quiet_until = start + window_s
    return alerts
