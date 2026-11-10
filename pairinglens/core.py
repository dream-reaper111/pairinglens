"""Analyze non-secret SMP pairing metadata conservatively."""

from datetime import datetime
import json

IO = {0: "DisplayOnly", 1: "DisplayYesNo", 2: "KeyboardOnly", 3: "NoInputNoOutput", 4: "KeyboardDisplay"}
ALLOWED = {"pairing_request", "pairing_response", "encryption_change", "bonded", "reconnect", "pairing_failed", "disconnected"}


def decode_pairing_pdu(hex_text: str) -> dict:
    try:
        data = bytes.fromhex(hex_text)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid SMP hex") from exc
    if len(data) != 7 or data[0] not in (1, 2):
        raise ValueError("only Pairing Request/Response metadata PDUs are accepted")
    if data[1] not in IO or not 7 <= data[4] <= 16:
        raise ValueError("invalid IO capability or key size")
    return {"event": "pairing_request" if data[0] == 1 else "pairing_response",
            "io_capability": IO[data[1]], "oob_present": bool(data[2]),
            "auth_req": data[3], "max_key_size": data[4],
            "initiator_key_distribution_bits": data[5],
            "responder_key_distribution_bits": data[6]}


def analyze(trace: dict) -> dict:
    if not isinstance(trace, dict) or not isinstance(trace.get("events"), list) or len(trace["events"]) > 10000:
        raise ValueError("invalid pairing trace")
    if len(json.dumps(trace)) > 2_000_000:
        raise ValueError("trace exceeds 2 MB")
    events = []
    for item in trace["events"]:
        if not isinstance(item, dict):
            raise ValueError("invalid event")
        if "pdu_hex" in item:
            # Only non-secret request/response metadata are accepted; reject all other PDUs.
            safe = decode_pairing_pdu(item["pdu_hex"])
        else:
            safe = {key: item[key] for key in ("event", "io_capability", "oob_present", "auth_req", "max_key_size", "initiator_key_distribution_bits", "responder_key_distribution_bits", "encrypted", "reason") if key in item}
        if safe.get("event") not in ALLOWED:
            raise ValueError("unsupported event type")
        stamp = item.get("timestamp")
        if not isinstance(stamp, str) or datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("timestamp requires timezone")
        safe["timestamp"] = stamp
        events.append(safe)
    events.sort(key=lambda x: x["timestamp"])
    request = next((x for x in events if x["event"] == "pairing_request"), None)
    response = next((x for x in events if x["event"] == "pairing_response"), None)
    indicators = []
    method = "undetermined"
    mode = "undetermined"
    if request and response:
        a, b = request.get("auth_req", 0), response.get("auth_req", 0)
        if not isinstance(a, int) or not isinstance(b, int):
            raise ValueError("invalid auth flags")
        mode = "LE Secure Connections indicated" if a & b & 0x08 else "legacy or unverified"
        if not (a & b & 0x04):
            method = "Just Works indicated"
            indicators.append("MITM protection not requested by both sides")
        elif request.get("oob_present") and response.get("oob_present"):
            method = "OOB indicated"
        elif request.get("io_capability") == "DisplayYesNo" and response.get("io_capability") == "DisplayYesNo" and a & b & 0x08:
            method = "numeric comparison candidate"
        else:
            method = "passkey or other MITM-capable method candidate"
        if min(request.get("max_key_size", 16), response.get("max_key_size", 16)) < 16:
            indicators.append("negotiated maximum key size below 16 bytes")
        if bool(a & 0x08) != bool(b & 0x08):
            indicators.append("Secure Connections capability mismatch; review downgrade context")
    encryption = [x["encrypted"] for x in events if x["event"] == "encryption_change" and isinstance(x.get("encrypted"), bool)]
    return {"source": trace.get("source", "offline metadata"), "events": events,
            "pairing_mode_indicator": mode, "method_indicator": method,
            "encryption_observed": True if True in encryption else False if encryption else None,
            "bonding_events": sum(x["event"] == "bonded" for x in events),
            "reconnections": sum(x["event"] == "reconnect" for x in events),
            "indicators": indicators, "security_posture": "inferred from trace metadata; device security unverified",
            "recommendations": ["Verify pairing UX, MITM protection, key size, and encryption on an authorized device with vendor documentation and controlled tests."]}


def compare(first: dict, second: dict) -> dict:
    return {"pairing_mode_changed": first["pairing_mode_indicator"] != second["pairing_mode_indicator"],
            "method_changed": first["method_indicator"] != second["method_indicator"],
            "encryption_observation_changed": first["encryption_observed"] != second["encryption_observed"],
            "new_indicators": sorted(set(second["indicators"]) - set(first["indicators"]))}
