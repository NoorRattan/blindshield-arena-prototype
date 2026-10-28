"""Owner-local demo PKI. Private authority keys stay outside the repository."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import ipaddress
import json
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from arena.broker.provision import write_private
from arena.contracts.common import Principal
from arena.model_runtime import BACKEND
from .admission import authority_public, key_from_file


def provision(directory, key_directory, store, domain):
    directory, key_directory = Path(directory), Path(key_directory).resolve()
    if key_directory.is_relative_to(BACKEND.parent):
        raise ValueError("AUTHORITY_KEYS_MUST_BE_OUTSIDE_REPOSITORY")
    directory.mkdir(parents=True, exist_ok=False)
    ca_bytes = (BACKEND / "infra/owner-delegated-n08/demo-ca-certificate.pem").read_bytes()
    ca = x509.load_pem_x509_certificate(ca_bytes)
    ca_key = serialization.load_pem_private_key((key_directory / "demo-ca-private.pem").read_bytes(), password=None)
    public_der = lambda key: key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if public_der(ca.public_key()) != public_der(ca_key.public_key()):
        raise ValueError("PINNED_DEMO_CA_KEY_MISMATCH")
    recorder, witness = (key_from_file(key_directory / (role + "-private.pem")) for role in ("recorder", "witness"))
    if recorder.public_key().public_bytes_raw() != authority_public("recorder") or witness.public_key().public_bytes_raw() != authority_public("witness"):
        raise ValueError("PINNED_EVIDENCE_AUTHORITY_MISMATCH")
    now = datetime.now(timezone.utc)
    if not ca.not_valid_before_utc <= now < ca.not_valid_after_utc:
        raise ValueError("PINNED_DEMO_CA_EXPIRED")
    (directory / "ca.pem").write_bytes(ca_bytes)
    expires = min(now + timedelta(hours=12), ca.not_valid_after_utc)
    def issue(label, server=False, *, uri_principal=None):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)]))
            .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(expires)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True))
        if server:
            cert = cert.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        elif uri_principal is not None:
            cert = cert.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(
                "urn:arena:principal:" + uri_principal
            )]), critical=False)
        cert = cert.sign(ca_key, hashes.SHA256())
        write_private(directory / (label + ".key"), key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (directory / (label + ".pem")).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    issue("server", True)
    principals, clients = {}, {}
    for role in ("operator", "red", "blue-human", "auditor"):
        label = "client-" + role
        principal = Principal(subject_id=role, role=role, domain_id=domain,
            expires_at=expires.isoformat(timespec="seconds").replace("+00:00", "Z"))
        store.provision(issue(label), principal)
        principals[role] = principal
        context = ssl.create_default_context(cafile=str(directory / "ca.pem"))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(directory / (label + ".pem")), str(directory / (label + ".key")))
        clients[role] = context
    # This certificate is not registered as an API principal. The separate
    # anchor process accepts only this exact URI SAN over mutually authenticated
    # loopback TLS and never trusts caller-supplied principal text.
    issue("client-recorder", uri_principal="n08-prototype-recorder-001")
    write_private(directory / "clients.json", json.dumps({r: "client-" + r for r in principals}).encode())
    return principals, clients, recorder, witness
