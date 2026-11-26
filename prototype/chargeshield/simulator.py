"""Synthetic OCPP traffic generator for a small fleet of charging stations.

Messages use the OCPP-J frame format: [2, uniqueId, action, payload].
The message set is a simplified subset of OCPP 1.6 / 2.0.1; for example
StartTransaction carries its own transactionId to keep the demo short.

Every generated message carries a ground-truth label ("normal" or the name
of the attack), which lets us measure detection rate and false positives.
"""
import json
import random
from dataclasses import dataclass

HEARTBEAT_S = 300        # charger sends a Heartbeat every 5 minutes
METER_INTERVAL_S = 60    # MeterValues every minute while charging

# Attacks that the protocol-aware inspector (Layer 2) should catch per message
L2_ATTACKS = ["malformed", "out_of_state", "meter_rollback", "impossible_power"]
# Attacks that only show up as unusual behaviour over a time window (Layer 3)
L3_ATTACKS = ["auth_bruteforce", "message_flood", "config_tamper"]
# Attack that only shows up when the whole fleet is observed together
FLEET_ATTACKS = ["fleet_load_attack"]


@dataclass
class Event:
    t: float            # seconds since the start of the simulation
    charger: str        # ChargePointId
    direction: str      # "cp->csms" (charger to server) or "csms->cp"
    raw: str            # the OCPP-J frame exactly as sent on the wire
    label: str = "normal"


class FleetSimulator:
    def __init__(self, n_chargers=20, hours=24, seed=1):
        self.rng = random.Random(seed)
        self.hours = hours
        # rated power in watts: 22 kW AC or 50 kW DC chargers
        self.chargers = {f"CP{i:03d}": self.rng.choice([22000, 50000])
                         for i in range(1, n_chargers + 1)}
        self.valid_tags = {f"TAG{i:04d}" for i in range(200)}
        self.events: list[Event] = []
        self.attack_instances: list[dict] = []
        self._uid = 0
        self._tx = 1000

    # ------------------------------------------------------------------
    def _emit(self, t, cp, action, payload, direction="cp->csms",
              label="normal", raw=None):
        self._uid += 1
        if raw is None:
            raw = json.dumps([2, f"m{self._uid}", action, payload])
        self.events.append(Event(t, cp, direction, raw, label))

    # ------------------------------------------------------------------
    def generate_normal(self):
        rng, end = self.rng, self.hours * 3600
        tags = sorted(self.valid_tags)
        for cp, rated in self.chargers.items():
            self._emit(rng.uniform(0, 5), cp, "BootNotification",
                       {"chargePointVendor": "DemoVendor",
                        "chargePointModel": f"M{rated // 1000}"})
            t = rng.uniform(0, HEARTBEAT_S)
            while t < end:
                self._emit(t, cp, "Heartbeat", {})
                t += HEARTBEAT_S + rng.uniform(-5, 5)

            meter = rng.randint(100_000, 5_000_000)  # lifetime energy register (Wh)
            t = rng.uniform(600, 3 * 3600)
            while t < end - 3600:
                tag = rng.choice(tags)
                if rng.random() < 0.05:   # normal noise: expired / mistyped card
                    self._emit(t - 20, cp, "Authorize", {"idTag": f"OLD{rng.randint(0, 99)}"})
                self._emit(t, cp, "Authorize", {"idTag": tag})
                self._emit(t + 5, cp, "StatusNotification",
                           {"connectorId": 1, "status": "Preparing", "errorCode": "NoError"})
                self._tx += 1
                tx = self._tx
                self._emit(t + 10, cp, "StartTransaction",
                           {"connectorId": 1, "idTag": tag, "meterStart": meter,
                            "transactionId": tx, "timestamp": t + 10})
                self._emit(t + 11, cp, "StatusNotification",
                           {"connectorId": 1, "status": "Charging", "errorCode": "NoError"})
                duration = rng.uniform(20 * 60, 3 * 3600)
                power = rated * rng.uniform(0.3, 0.95)
                tt = t + 10
                while tt + METER_INTERVAL_S < min(t + 10 + duration, end):
                    tt += METER_INTERVAL_S
                    meter += int(power * rng.uniform(0.9, 1.02) * METER_INTERVAL_S / 3600)
                    self._emit(tt, cp, "MeterValues",
                               {"connectorId": 1, "transactionId": tx,
                                "meterValue": [{"timestamp": tt, "energyWh": meter}]})
                self._emit(tt + 1, cp, "StopTransaction",
                           {"transactionId": tx, "meterStop": meter,
                            "timestamp": tt + 1, "reason": "EVDisconnected"})
                self._emit(tt + 2, cp, "StatusNotification",
                           {"connectorId": 1, "status": "Available", "errorCode": "NoError"})
                t = tt + rng.uniform(15 * 60, 4 * 3600)

            # legitimate smart-charging and configuration commands from the server
            for _ in range(rng.randint(0, 2)):
                self._emit(rng.uniform(0, end), cp, "SetChargingProfile",
                           {"connectorId": 1, "limitW": int(rated * rng.uniform(0.5, 1.0))},
                           direction="csms->cp")
            if rng.random() < 0.3:
                self._emit(rng.uniform(0, end), cp, "ChangeConfiguration",
                           {"key": "HeartbeatInterval", "value": "300"},
                           direction="csms->cp")
        return self

    # ------------------------------------------------------------------
    def inject_attacks(self):
        rng = self.rng
        meter_events = [e for e in self.events if '"MeterValues"' in e.raw]

        # --- Layer 2 attacks: single forged messages --------------------
        for e in rng.sample(meter_events, 5):           # meter goes backwards
            p = json.loads(e.raw)[3]
            mv = p["meterValue"][0]
            self._emit(e.t + 0.5, e.charger, "MeterValues",
                       {"connectorId": 1, "transactionId": p["transactionId"],
                        "meterValue": [{"timestamp": e.t + 0.5,
                                        "energyWh": mv["energyWh"] - 5000}]},
                       label="meter_rollback")
        for e in rng.sample(meter_events, 5):           # physically impossible jump
            p = json.loads(e.raw)[3]
            mv = p["meterValue"][0]
            self._emit(e.t + 0.5, e.charger, "MeterValues",
                       {"connectorId": 1, "transactionId": p["transactionId"],
                        "meterValue": [{"timestamp": e.t + 0.5,
                                        "energyWh": mv["energyWh"] + 2000}]},
                       label="impossible_power")
        cps = list(self.chargers)
        for i in range(5):                              # spoofed charger, fake transaction
            t = rng.uniform(3600, self.hours * 3600 - 3600)
            self._emit(t, rng.choice(cps), "MeterValues",
                       {"connectorId": 1, "transactionId": 900_000 + i,
                        "meterValue": [{"timestamp": t, "energyWh": 1_000_000}]},
                       label="out_of_state")
        malformed = [
            '[2, "x1", "MeterValues", {"connectorId": 1, "transactionId": "1 OR 1=1", "meterValue": []}]',
            '[2, "x2", "Authorize", {}]',
            '[2, "x3", "Heartbeat", {',
            '[2, "x4", "MeterValues", {"connectorId": 1, "transactionId": 5, "meterValue": [{"timestamp": 1, "energyWh": "lots"}]}]',
            '[2, "x5", "GetDiagnosticsDump", {"path": "/etc/shadow"}]',
        ]
        for raw in malformed:
            self._emit(rng.uniform(0, self.hours * 3600), rng.choice(cps), None, None,
                       label="malformed", raw=raw)

        # --- Layer 3 attacks: behaviour over one hour on one charger -----
        used = set()
        def pick_slot():
            while True:
                slot = (rng.choice(cps), rng.randint(2, self.hours - 2))
                if slot not in used:
                    used.add(slot)
                    return slot

        for _ in range(2):                              # guessing RFID card numbers
            cp, h = pick_slot()
            for _ in range(40):
                self._emit(h * 3600 + rng.uniform(0, 3500), cp, "Authorize",
                           {"idTag": f"ATK{rng.randint(0, 99999):05d}"}, label="auth_bruteforce")
            self.attack_instances.append({"type": "auth_bruteforce", "charger": cp, "hour": h})
        for _ in range(2):                              # message flood (DoS on the server)
            cp, h = pick_slot()
            for _ in range(400):
                self._emit(h * 3600 + rng.uniform(0, 3500), cp, "Heartbeat", {},
                           label="message_flood")
            self.attack_instances.append({"type": "message_flood", "charger": cp, "hour": h})
        for _ in range(2):                              # attacker reconfiguring a charger
            cp, h = pick_slot()
            for key in ["AuthorizeRemoteTxRequests", "LocalAuthorizeOffline",
                        "AllowOfflineTxForUnknownId", "SecurityProfile"] * 3:
                self._emit(h * 3600 + rng.uniform(0, 3500), cp, "ChangeConfiguration",
                           {"key": key, "value": "true"}, direction="csms->cp",
                           label="config_tamper")
            self.attack_instances.append({"type": "config_tamper", "charger": cp, "hour": h})

        # --- Fleet attack: many chargers switched at once -----------------
        t0 = rng.uniform(10 * 3600, 20 * 3600)
        for cp in rng.sample(cps, 15):
            self._emit(t0 + rng.uniform(0, 120), cp, "SetChargingProfile",
                       {"connectorId": 1, "limitW": self.chargers[cp]},
                       direction="csms->cp", label="fleet_load_attack")
        self.attack_instances.append({"type": "fleet_load_attack", "start": t0, "end": t0 + 120})
        return self

    # ------------------------------------------------------------------
    def sorted_events(self):
        return sorted(self.events, key=lambda e: e.t)
