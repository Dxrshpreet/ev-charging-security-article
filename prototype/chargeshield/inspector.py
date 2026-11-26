"""Layer 2: protocol-aware inspection of OCPP messages.

In a real deployment this would run inside a WebSocket proxy at the entrance
of the CSMS, where TLS has already been removed. Here it receives one message
at a time and returns FORWARD, ALERT or BLOCK, mirroring Algorithm 1 in the
paper:
  1. schema check      - is the message well formed for its action?
  2. state check       - is the message allowed in the charger's current state?
  3. plausibility check - does the meter value obey physics?
"""
import json
from dataclasses import dataclass

NUM = (int, float)

# Minimal schemas: required field -> expected type
SCHEMAS = {
    "BootNotification":   {"chargePointVendor": str, "chargePointModel": str},
    "Heartbeat":          {},
    "Authorize":          {"idTag": str},
    "StatusNotification": {"connectorId": int, "status": str, "errorCode": str},
    "StartTransaction":   {"connectorId": int, "idTag": str, "meterStart": int,
                           "transactionId": int, "timestamp": NUM},
    "MeterValues":        {"connectorId": int, "transactionId": int, "meterValue": list},
    "StopTransaction":    {"transactionId": int, "meterStop": int,
                           "timestamp": NUM, "reason": str},
    "SetChargingProfile": {"connectorId": int, "limitW": int},
    "ChangeConfiguration": {"key": str, "value": str},
}

POWER_TOLERANCE = 1.10   # allow 10 % above rated power for meter rounding


@dataclass
class Verdict:
    decision: str   # FORWARD, ALERT or BLOCK
    reason: str = ""


def parse_and_validate(raw):
    """Schema check only. Returns (action, payload) or raises ValueError."""
    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        raise ValueError("invalid JSON")
    if not (isinstance(msg, list) and len(msg) == 4 and msg[0] == 2):
        raise ValueError("not an OCPP-J CALL frame")
    action, payload = msg[2], msg[3]
    if action not in SCHEMAS:
        raise ValueError(f"unknown action '{action}'")
    if not isinstance(payload, dict):
        raise ValueError("payload is not an object")
    for field, typ in SCHEMAS[action].items():
        if field not in payload:
            raise ValueError(f"missing field '{field}'")
        if not isinstance(payload[field], typ) or isinstance(payload[field], bool):
            raise ValueError(f"wrong type for '{field}'")
    if action == "MeterValues":
        if not payload["meterValue"]:
            raise ValueError("empty meterValue")
        for mv in payload["meterValue"]:
            if not (isinstance(mv, dict) and isinstance(mv.get("timestamp"), NUM)
                    and isinstance(mv.get("energyWh"), int)):
                raise ValueError("bad meterValue entry")
    return action, payload


class ProtocolInspector:
    def __init__(self, rated_power_w):
        self.rated = rated_power_w          # ChargePointId -> rated power (W)
        self.state = {}                     # ChargePointId -> per-charger state

    def _st(self, cp):
        return self.state.setdefault(cp, {"tx": None, "last_e": None, "last_t": None})

    def inspect(self, event):
        try:
            action, p = parse_and_validate(event.raw)
        except ValueError as err:
            return Verdict("BLOCK", f"schema: {err}")

        if event.direction != "cp->csms":
            return Verdict("FORWARD")       # server commands are handled by the policy layer

        st = self._st(event.charger)

        if action == "StartTransaction":
            if st["tx"] is not None:
                return Verdict("ALERT", "state: StartTransaction while already charging")
            if st["last_e"] is not None and p["meterStart"] < st["last_e"]:
                return Verdict("ALERT", "plausibility: meterStart lower than last reading")
            st.update(tx=p["transactionId"], last_e=p["meterStart"], last_t=p["timestamp"])

        elif action == "MeterValues":
            if st["tx"] != p["transactionId"]:
                return Verdict("ALERT", f"state: MeterValues for unknown transaction {p['transactionId']}")
            mv = p["meterValue"][-1]
            d_e = mv["energyWh"] - st["last_e"]
            d_t = mv["timestamp"] - st["last_t"]
            if d_e < 0:
                return Verdict("ALERT", f"plausibility: meter went backwards by {-d_e} Wh")
            if d_t <= 0:
                return Verdict("ALERT", "plausibility: timestamp not increasing")
            power_w = d_e * 3600 / d_t
            if power_w > self.rated[event.charger] * POWER_TOLERANCE:
                return Verdict("ALERT", f"plausibility: {power_w / 1000:.0f} kW exceeds rated "
                                        f"{self.rated[event.charger] / 1000:.0f} kW")
            st.update(last_e=mv["energyWh"], last_t=mv["timestamp"])

        elif action == "StopTransaction":
            if st["tx"] != p["transactionId"]:
                return Verdict("ALERT", "state: StopTransaction for unknown transaction")
            st.update(tx=None, last_e=p["meterStop"], last_t=p["timestamp"])

        return Verdict("FORWARD")


def baseline_signature_check(event):
    """Stand-in for a generic, protocol-unaware IDS: it can only notice
    traffic that is syntactically broken. It does not track state or
    meaning, so well-formed but forged messages pass."""
    try:
        parse_and_validate(event.raw)
        return False
    except ValueError:
        return True
