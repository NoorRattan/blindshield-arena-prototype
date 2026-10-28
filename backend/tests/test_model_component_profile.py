"""Component gate regressions; synthetic bytes do not establish runtime fit."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from arena import model_runtime as module
from arena.contracts.crypto import sha256
from arena.integration.types import AdmissionLock
from arena.ports import DependencyUnavailable


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    pins = json.loads((module.BACKEND / "config/n04-sources.json").read_bytes())
    pins.update(model_sha256=sha256(b"model"), model_bytes=5,
                model_license_sha256=sha256(b"license"), model_readme_sha256=sha256(b"card"))
    (tmp_path / "config").mkdir()
    (tmp_path / "config/n04-sources.json").write_text(json.dumps(pins))
    recipe = tmp_path / "infra/cells/Dockerfile.model"
    recipe.parent.mkdir(parents=True)
    recipe.write_bytes(b"FROM pinned\n")
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    model = model_dir / pins["model_filename"]
    model.write_bytes(b"model")
    (model_dir / "LICENSE").write_bytes(b"license")
    (model_dir / "README.md").write_bytes(b"card")
    admission = AdmissionLock(
        schema_version="arena-n04-admission.v2", runtime_source_sha256={"src/arena/model_runtime.py":"a"*64},
        **{name: pins[name] for name in ("model_repository", "model_revision", "model_filename", "model_sha256", "model_license", "model_license_sha256", "llama_image", "llama_source_revision", "defense_python_base")},
        tokenizer_binding="EMBEDDED_IN_EXACT_GGUF", defense_image="sha256:"+"b"*64,
        defense_source_sha256="c"*64, corpus_receipt_sha256="d"*64,
        context_tokens=2048,input_token_cap=1536,max_output_tokens=64,deadline_seconds=45,
        turn_limit=24,artifact_reservation_per_turn=8,
        claim_scope="N04_LOCAL_SINGLE_LANE_ONLY_NOT_FULL_ARENA_ACCEPTANCE",
    )
    profile = module.ModelProfile(
        schema_version="arena-model-component-profile.v1",profile_id="qwen25-05b-cpu-component-v1",
        authorization="BOUNDED_STEP2_MODEL_COMPONENT_VALIDATION_ONLY",
        artifact_label="OWNER-DELEGATED, SELF-ATTESTED, PROTOTYPE-SCOPE",
        n08_workload_authorized=False,admission=admission,model_bytes=5,
        model_readme_sha256=pins["model_readme_sha256"],assembled_image_id="sha256:"+"e"*64,
        dockerfile_sha256=module.file_digest(recipe),publisher_observation_sha256=sha256(b"publisher"),
        host_available_memory_floor_bytes=8589934592,
    )
    monkeypatch.setattr(module,"BACKEND",tmp_path)
    return profile,model,recipe


def test_exact_assets_pass_component_preflight(prepared):
    profile,model,_=prepared
    module.validate_assets(profile,model)


@pytest.mark.parametrize("changed", ["model", "LICENSE", "README.md", "recipe"])
def test_changed_assets_or_recipe_are_rejected(prepared,changed):
    profile,model,recipe=prepared
    path = model if changed=="model" else recipe if changed=="recipe" else model.parent/changed
    path.write_bytes(b"corrupt")
    with pytest.raises(DependencyUnavailable):
        module.validate_assets(profile,model)


def test_missing_model_refuses_before_any_docker_operation(prepared,monkeypatch):
    profile,model,_=prepared
    model.unlink()
    monkeypatch.setattr(module,"docker",lambda *a,**kw: pytest.fail("Docker must not run"))
    with pytest.raises(DependencyUnavailable,match="MODEL_FILE_MISSING"):
        module.validate_assets(profile,model)


def test_component_profile_cannot_grant_n08_or_accept_mutable_image(prepared):
    profile,_,_=prepared
    for change in ({"n08_workload_authorized":True},{"assembled_image_id":"model:latest"},{"authorization":"FORCE_RUN"}):
        with pytest.raises(ValidationError):
            module.ModelProfile.model_validate(profile.model_dump()|change)


def test_wrong_assembled_image_identity_is_rejected(prepared,monkeypatch):
    profile,_,_=prepared
    monkeypatch.setattr(module,"ensure_local_docker",lambda:None)
    monkeypatch.setattr(module,"docker",lambda *a,**kw:b'[{"Id":"wrong","Config":{},"RootFS":{}}]')
    with pytest.raises(DependencyUnavailable,match="IMAGE_BINDING_MISMATCH"):
        module.validate_image(profile)


def test_missing_publisher_observation_prevents_start(prepared,tmp_path,monkeypatch):
    profile,model,_=prepared
    profile_path=tmp_path/"profile.json"
    profile_path.write_text(profile.model_dump_json())
    runtime=module.ModelCellRuntime(profile_path,model,tmp_path/"artifacts/cell")
    monkeypatch.setattr(module,"validate_image",lambda p:pytest.fail("image must not be inspected"))
    with pytest.raises(DependencyUnavailable,match="PUBLISHER_OBSERVATION_CHANGED"):
        runtime.start()


def test_low_host_capacity_prevents_start(prepared,tmp_path,monkeypatch):
    profile,model,_=prepared
    profile_path=tmp_path/"profile.json"
    profile_path.write_text(profile.model_dump_json())
    (tmp_path/"publisher-observation.json").write_bytes(b"publisher")
    runtime=module.ModelCellRuntime(profile_path,model,tmp_path/"artifacts/cell")
    monkeypatch.setattr(module,"host_available_memory",lambda:8589934591)
    monkeypatch.setattr(module,"validate_image",lambda p:pytest.fail("image must not be inspected"))
    with pytest.raises(DependencyUnavailable,match="CAPACITY_BELOW_FLOOR"):
        runtime.start()
