"""Offline sealed-list coverage and lineage, after normal signed/opening checks."""
import base64
import json

from arena.contracts.crypto import commitment


def verify_batch_openings(plaintexts):
    objects = [json.loads(value) for value in plaintexts.values()]
    manifests = [value["sealed"]["manifest"] for value in objects if "sealed" in value]
    if len(manifests) != 1 or manifests[0]["profile"]["request"]["interaction_mode"] != "SEALED_BATCH":
        raise ValueError("EXACT_SEALED_BATCH_MANIFEST_REQUIRED")
    plan = manifests[0].get("prototype_batch", {})
    if plan.get("schema_version") != "arena-prototype-batch-plan.v1" or not 1 <= len(plan.get("items", [])) <= 24:
        raise ValueError("VERSIONED_BATCH_PLAN_REQUIRED")
    inputs = []
    for value in objects:
        if value.get("kind") == "INPUT_OPENING":
            inputs.append(json.loads(base64.b64decode(value["content_base64"], validate=True)))
    items = plan["items"]
    if [{k: item[k] for k in ("item_id", "artifact_id")} for item in items] != manifests[0]["items"]:
        raise ValueError("SEALED_MANIFEST_ITEM_SET_MISMATCH")
    originals = [value for value in objects if "prototype_batch_item_id" in value]
    if len(inputs) != len(items) or len({i["item_id"] for i in items}) != len(items):
        raise ValueError("EXACT_BATCH_COVERAGE_REQUIRED")
    if len(originals) != len(items):
        raise ValueError("SIGNED_BATCH_ITEM_BINDINGS_REQUIRED")
    lane_sessions, seen = {}, set()
    for index, item in enumerate(items):
        if item["lane"] != index % 3 or item["turn_index"] != index // 3:
            raise ValueError("FROZEN_BATCH_ORDER_REJECTED")
        bound = [value for value in originals if value["prototype_batch_item_id"] == item["item_id"]]
        if len(bound) != 1 or bound[0]["prototype_batch_lane"] != item["lane"]:
            raise ValueError("EXACT_SIGNED_BATCH_ITEM_BINDING_REQUIRED")
        matches = [value for value in inputs if value["turn_id"] == bound[0]["turn_id"] and value["turn_index"] == item["turn_index"]
            and value["provenance"] == item["provenance"]
            and commitment(base64.b64decode(value["original_utf8_base64"], validate=True), bytes.fromhex(item["content_nonce_hex"])) == item["content_commitment"]]
        if len(matches) != 1 or matches[0]["turn_id"] in seen:
            raise ValueError("SEALED_ITEM_SUBSTITUTION_OR_DUPLICATION")
        value = matches[0]
        lane = item["lane"]
        old = lane_sessions.setdefault(lane, value["session_id"])
        if old != value["session_id"] or any(s == old for l, s in lane_sessions.items() if l != lane):
            raise ValueError("BATCH_LANE_SESSION_BINDING_REJECTED")
        seen.add(value["turn_id"])
    return {"prototype_batch_verified": True, "sealed_items_verified": len(items)}
