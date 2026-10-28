"""Separate process mTLS identity, persistence and external-ledger deletion refusal."""
from datetime import datetime, timedelta, timezone
import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from arena.contracts.common import Context
from arena.contracts.evidence import Event
from arena.contracts.crypto import event_digest
from arena.recovery.anchor import RECORDER_PRINCIPAL, RecoveryAnchorError
from arena.recovery.process import RecoveryAnchorProcess


def _write_key(path, key):
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def _pki(root):
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test anchor CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256()))
    ca_path = root / "ca.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def issue(name, server=False):
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=2))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True))
        if server:
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        else:
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier("urn:arena:principal:" + RECORDER_PRINCIPAL)]), critical=False)
        certificate = builder.sign(ca_key, hashes.SHA256())
        cert_path, key_path = root / (name + ".pem"), root / (name + ".key")
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        _write_key(key_path, key)
        return cert_path, key_path

    server_cert, server_key = issue("server", True)
    recorder_cert, recorder_key = issue("recorder")
    return ca_path, server_cert, server_key, recorder_cert, recorder_key


def _manager(root, key, certs):
    ca, server_cert, server_key, recorder_cert, recorder_key = certs
    private_path = root / "anchor-private.pem"
    if not private_path.exists():
        _write_key(private_path, key)
    return RecoveryAnchorProcess(
        data_directory=root / "external-anchor",
        private_key_path=private_path,
        public_key=key.public_key().public_bytes_raw(),
        authority_id="test-anchor", key_id="test-anchor-key",
        ca=ca, server_certificate=server_cert, server_private_key=server_key,
        recorder_certificate=recorder_cert, recorder_private_key=recorder_key,
    )


def _event(context):
    return Event(**context.model_dump(), session_id=None, turn_id=None, turn_index=None,
        event_type="MANIFEST_SEALED", outcome_code="OK", artifact_ciphertext_refs=(), duration_us=0,
        schema_version="arena.v2", sequence=1, previous_digest="0" * 64,
        actor_id="test-recorder", public_manifest_digest="a" * 64,
        utc_time="2026-10-26T12:00:00Z")


def test_mtls_external_process_persists_signed_records_and_refuses_missing_ledger(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    certs = _pki(tmp_path)
    manager = _manager(tmp_path, key, certs)
    context = Context(domain_id="10000000-0000-4000-8000-000000000001",
        experiment_id="20000000-0000-4000-8000-000000000002", epoch=1)
    event = _event(context)
    try:
        client = manager.start()
        client.health()
        client.prepare(event)
        client.commit(event)
        state = client.verify_events(context, [event])
        assert state["event_sequence"] == 1 and state["event_root"] == event_digest(event)
    finally:
        manager.stop()

    restarted = _manager(tmp_path, key, certs)
    try:
        client = restarted.start()
        assert len(client.records(context)) == 2
        assert client.verify_events(context, [event])["event_sequence"] == 1
    finally:
        restarted.stop()

    (tmp_path / "external-anchor" / "anchor.sqlite3").unlink()
    with pytest.raises(RecoveryAnchorError, match="ANCHOR_LEDGER_MISSING_OR_UNSAFE"):
        _manager(tmp_path, key, certs).start()


def test_read_only_startup_cannot_bootstrap_a_missing_anchor(tmp_path):
    key = ed25519.Ed25519PrivateKey.generate()
    certs = _pki(tmp_path)
    manager = _manager(tmp_path, key, certs)
    with pytest.raises(RecoveryAnchorError, match="ANCHOR_LEDGER_MISSING_OR_UNSAFE"):
        manager.start(require_existing=True)
    assert not (tmp_path / "anchor-instance.json").exists()
    assert not (tmp_path / "external-anchor" / "anchor.sqlite3").exists()
