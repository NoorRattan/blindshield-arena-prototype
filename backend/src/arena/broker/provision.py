"""Local developer credentials; no global trust store changes or evidence signing keys."""

from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from arena.contracts.common import Principal
from .config import BrokerConfig
from .store import Store


def write_private(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
        output.write(data)


def initialize(directory: Path, config: BrokerConfig):
    """Refuses to overwrite. Single-host dev layout intentionally holds ALL demo identities.

    Not a tenant key distribution layout. Windows permissions inherit the parent ACL;
    POSIX mode is best effort only. N05 deployment must provision distinct private mounts.
    """
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "arena local development CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
          .not_valid_after(now + timedelta(days=7)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True).sign(ca_key, hashes.SHA256()))
    write_private(directory / "ca.key", ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (directory / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    master_key = os.urandom(32)
    write_private(directory / "vault.key", master_key)
    store = Store(directory / "broker.sqlite3", master_key)
    store.initialize()

    def issue(label, server=False):
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)]))
                   .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=24))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
        if server:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        certificate = builder.sign(ca_key, hashes.SHA256())
        write_private(directory / f"{label}.key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (directory / f"{label}.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        return hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()

    issue("server", True)
    identities = {}
    # Deterministic local labels avoid using config strings as filesystem paths.
    for profile in config.profiles:
        members = [("operator", "operator"), (profile.red_subject_id, "red"), (profile.blue_subject_id, "blue-human"),
                   *[(subject, "auditor") for subject in profile.auditor_subject_ids]]
        for subject, role in members:
            binding = (subject, role, profile.domain_id)
            if subject in identities:
                if identities[subject]["binding"] != list(binding):
                    raise ValueError("Inconsistent dev identity binding")
                continue
            label = f"client-{len(identities)}"
            principal = Principal(subject_id=subject, role=role, domain_id=profile.domain_id,
                                  expires_at=(now + timedelta(hours=24)).isoformat(timespec="seconds").replace("+00:00", "Z"))
            store.provision(issue(label), principal)
            identities[subject] = {"label": label, "binding": list(binding)}
    write_private(directory / "identities.json", json.dumps(identities, indent=2).encode("utf-8"))
    write_private(directory / "config.json", config.model_dump_json(indent=2).encode("utf-8"))
    return store
