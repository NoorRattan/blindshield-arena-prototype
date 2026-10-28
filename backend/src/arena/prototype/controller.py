"""Bind sealed item identity into the signed turn's encrypted original artifact."""
from contextlib import closing

from arena.integration.controller import N04Controller
from arena.ports import DependencyUnavailable


class PrototypeController(N04Controller):
    def _artifact(self, value, classification):
        if (self.runtime.purpose == "SERVICE" and classification == "PRIVATE_PAYLOAD"
            and "original_utf8_base64" in value and "provenance" in value):
            with closing(self.store.connect()) as conn:
                row = dict(conn.execute("SELECT * FROM experiments WHERE id=?", (self.identifier,)).fetchone())
                turn = conn.execute("SELECT t.payload_ref,s.lane FROM turns t JOIN sessions s ON s.id=t.session_id WHERE t.id=?", (value["turn_id"],)).fetchone()
            from arena.broker.config import Profile
            if Profile.model_validate_json(row["config_json"]).request.interaction_mode == "SEALED_BATCH":
                items = [item for item in self.broker.frozen_batch(row)["items"] if item["artifact_id"] == turn["payload_ref"]]
                if len(items) != 1 or items[0]["lane"] != turn["lane"] or items[0]["turn_index"] != value["turn_index"]:
                    raise DependencyUnavailable("SEALED_BATCH_ORIGINAL_BINDING_REJECTED")
                value = dict(value, prototype_batch_item_id=items[0]["item_id"], prototype_batch_lane=turn["lane"])
        return super()._artifact(value, classification)
