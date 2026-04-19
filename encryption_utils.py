from __future__ import annotations

import json
import os
import re
import shutil
import struct
from base64 import b64decode, b64encode
from ctypes import CDLL, POINTER, Structure, c_char_p, c_int, c_uint32, create_string_buffer, pointer
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from importlib.util import find_spec
from pathlib import Path
from time import perf_counter
from typing import Any

from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509.oid import NameOID

MAGIC = b"CSENC1"
PBKDF2_ITERATIONS = 200_000
CHUNK_SIZE = 64 * 1024
HISTORY_FILE = Path(__file__).resolve().parent / "encryption_history.json"
KEYS_DIR = Path(__file__).resolve().parent / "keys"


@dataclass(frozen=True)
class EncryptionResult:
    output_path: Path
    algorithm: str
    family: str
    execution_time_ms: float
    metadata: dict[str, Any]


@dataclass(frozen=True)
class DecryptionResult:
    output_path: Path
    algorithm: str
    family: str
    execution_time_ms: float
    metadata: dict[str, Any]


def _slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "_", value.strip().lower()).strip("_")
    return cleaned or "cle"


def _build_key_bundle_dir(label: str, suffix: str) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    bundle_dir = KEYS_DIR / f"{_slugify(label)}_{suffix}_{timestamp}"
    bundle_dir.mkdir(parents=True, exist_ok=False)
    return bundle_dir


def _write_key_bundle_metadata(bundle_dir: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    metadata_path = bundle_dir / "metadata.json"
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=True, indent=2), encoding="utf-8")
    return metadata


def _serialize_private_key(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _serialize_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _curve_from_name(curve_name: str) -> ec.EllipticCurve:
    curves = {
        "SECP256R1": ec.SECP256R1,
        "SECP384R1": ec.SECP384R1,
        "SECP521R1": ec.SECP521R1,
    }
    curve_class = curves.get(curve_name.upper())
    if curve_class is None:
        raise ValueError(f"Courbe ECC non supportee: {curve_name}")
    return curve_class()


def list_managed_key_bundles() -> list[dict[str, Any]]:
    if not KEYS_DIR.exists():
        return []

    bundles: list[dict[str, Any]] = []
    for metadata_path in sorted(KEYS_DIR.glob("*/metadata.json")):
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(metadata, dict):
            continue
        bundles.append(metadata)

    bundles.sort(key=lambda item: item.get("created_at_utc", ""), reverse=True)
    return bundles


def load_key_material(path: str | Path) -> bytes:
    return Path(path).read_bytes()


def delete_managed_key_bundle(bundle_id: str) -> None:
    bundle_dir = (KEYS_DIR / bundle_id).resolve()
    keys_root = KEYS_DIR.resolve()
    if bundle_dir.parent != keys_root or not bundle_dir.exists():
        raise ValueError("Bundle de cles introuvable.")
    shutil.rmtree(bundle_dir)


def generate_rsa_key_pair(label: str, key_size: int = 2048) -> dict[str, Any]:
    if key_size not in {2048, 3072, 4096}:
        raise ValueError("La taille de cle RSA doit etre 2048, 3072 ou 4096 bits.")

    bundle_dir = _build_key_bundle_dir(label, "rsa")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    private_key_path = bundle_dir / "private_key.pem"
    public_key_path = bundle_dir / "public_key.pem"
    private_key_path.write_bytes(_serialize_private_key(private_key))
    public_key_path.write_bytes(_serialize_public_key(public_key))

    metadata = {
        "id": bundle_dir.name,
        "label": label,
        "algorithm": "RSA",
        "kind": "key_pair",
        "created_at_utc": _utc_now(),
        "details": {"key_size": key_size},
        "files": {
            "private_key": str(private_key_path),
            "public_key": str(public_key_path),
        },
    }
    return _write_key_bundle_metadata(bundle_dir, metadata)


def generate_ecc_key_pair(label: str, curve_name: str = "SECP256R1") -> dict[str, Any]:
    curve = _curve_from_name(curve_name)
    bundle_dir = _build_key_bundle_dir(label, "ecc")
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()

    private_key_path = bundle_dir / "private_key.pem"
    public_key_path = bundle_dir / "public_key.pem"
    private_key_path.write_bytes(_serialize_private_key(private_key))
    public_key_path.write_bytes(_serialize_public_key(public_key))

    metadata = {
        "id": bundle_dir.name,
        "label": label,
        "algorithm": "ECC",
        "kind": "key_pair",
        "created_at_utc": _utc_now(),
        "details": {"curve": curve.name},
        "files": {
            "private_key": str(private_key_path),
            "public_key": str(public_key_path),
        },
    }
    return _write_key_bundle_metadata(bundle_dir, metadata)


def generate_self_signed_certificate(
    label: str,
    algorithm: str,
    common_name: str,
    validity_days: int = 365,
) -> dict[str, Any]:
    if validity_days < 1:
        raise ValueError("La duree de validite doit etre d'au moins 1 jour.")

    algorithm_name = algorithm.upper()
    bundle_dir = _build_key_bundle_dir(label, f"cert_{algorithm_name.lower()}")

    if algorithm_name == "RSA":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        details: dict[str, Any] = {"key_size": 2048}
    elif algorithm_name == "ECC":
        private_key = ec.generate_private_key(ec.SECP256R1())
        details = {"curve": "secp256r1"}
    else:
        raise ValueError(f"Algorithme de certificat non supporte: {algorithm}")

    public_key = private_key.public_key()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=private_key, algorithm=hashes.SHA256())
    )

    private_key_path = bundle_dir / "private_key.pem"
    public_key_path = bundle_dir / "public_key.pem"
    certificate_path = bundle_dir / "certificate.pem"
    private_key_path.write_bytes(_serialize_private_key(private_key))
    public_key_path.write_bytes(_serialize_public_key(public_key))
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    metadata = {
        "id": bundle_dir.name,
        "label": label,
        "algorithm": algorithm_name,
        "kind": "certificate",
        "created_at_utc": _utc_now(),
        "details": {
            **details,
            "common_name": common_name,
            "validity_days": validity_days,
        },
        "files": {
            "private_key": str(private_key_path),
            "public_key": str(public_key_path),
            "certificate": str(certificate_path),
        },
    }
    return _write_key_bundle_metadata(bundle_dir, metadata)


def list_dump_files(base_dir: Path) -> list[Path]:
    return sorted(base_dir.glob("*.dump"))


def list_encryptable_files(base_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in base_dir.iterdir()
        if path.is_file() and not path.name.startswith(".") and path.suffix.lower() != ".enc"
    )


def list_encrypted_files(base_dir: Path) -> list[Path]:
    return sorted(base_dir.glob("*.enc"))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _encode_b64(data: bytes) -> str:
    return b64encode(data).decode("ascii")


def _decode_b64(data: str) -> bytes:
    return b64decode(data.encode("ascii"))


def _pad_pkcs7(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _unpad_pkcs7(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Bloc chiffre invalide pour un depadding PKCS7.")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Padding PKCS7 invalide.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding PKCS7 incoherent.")
    return data[:-pad_len]


def _chunks(data: bytes, size: int) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]


def _derive_key(passphrase: str, key_size: int, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _derive_3des_key(passphrase: str, salt: bytes) -> bytes:
    seed = _derive_key(passphrase, 24, salt)
    for _ in range(8):
        try:
            return DES3.adjust_key_parity(seed)
        except ValueError:
            seed = _derive_key(seed.hex(), 24, salt)
    raise ValueError("Impossible de generer une cle Triple DES valide.")


class _TwofishKey(Structure):
    _fields_ = [("s", (c_uint32 * 4) * 256), ("K", c_uint32 * 40)]


class _TwofishEngine:
    def __init__(self, key: bytes) -> None:
        if not 1 <= len(key) <= 32:
            raise ValueError("La cle Twofish doit faire entre 1 et 32 octets.")

        spec = find_spec("_twofish")
        if spec is None or spec.origin is None:
            raise RuntimeError("Le module binaire _twofish est introuvable.")

        library = CDLL(spec.origin)
        self._prepare_key = library.exp_Twofish_prepare_key
        self._prepare_key.argtypes = [c_char_p, c_int, POINTER(_TwofishKey)]
        self._prepare_key.restype = None

        self._encrypt = library.exp_Twofish_encrypt
        self._encrypt.argtypes = [POINTER(_TwofishKey), c_char_p, c_char_p]
        self._encrypt.restype = None

        self._decrypt = library.exp_Twofish_decrypt
        self._decrypt.argtypes = [POINTER(_TwofishKey), c_char_p, c_char_p]
        self._decrypt.restype = None

        initialise = library.exp_Twofish_initialise
        initialise.argtypes = []
        initialise.restype = None
        initialise()

        self.key = _TwofishKey()
        self._prepare_key(key, len(key), pointer(self.key))

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Twofish travaille par blocs de 16 octets.")
        output = create_string_buffer(16)
        self._encrypt(pointer(self.key), block, output)
        return output.raw

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Twofish travaille par blocs de 16 octets.")
        output = create_string_buffer(16)
        self._decrypt(pointer(self.key), block, output)
        return output.raw


def _twofish_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    engine = _TwofishEngine(key)
    padded = _pad_pkcs7(plaintext, 16)
    previous = iv
    ciphertext = bytearray()

    for block in _chunks(padded, 16):
        mixed = bytes(a ^ b for a, b in zip(block, previous))
        encrypted = engine.encrypt_block(mixed)
        ciphertext.extend(encrypted)
        previous = encrypted

    return bytes(ciphertext)


def _twofish_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(ciphertext) % 16 != 0:
        raise ValueError("Le ciphertext Twofish doit etre aligne sur 16 octets.")

    engine = _TwofishEngine(key)
    previous = iv
    plaintext = bytearray()

    for block in _chunks(ciphertext, 16):
        decrypted = engine.decrypt_block(block)
        plaintext.extend(bytes(a ^ b for a, b in zip(decrypted, previous)))
        previous = block

    return _unpad_pkcs7(bytes(plaintext), 16)


def _build_encrypted_path(source_path: Path, suffix: str) -> Path:
    candidate = source_path.with_name(f"{source_path.name}.{suffix}.enc")
    if not candidate.exists():
        return candidate

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return source_path.with_name(f"{source_path.name}.{suffix}_{timestamp}.enc")


def _build_decrypted_path(source_path: Path, original_name: str | None) -> Path:
    target_name = original_name or source_path.stem
    candidate = source_path.with_name(target_name)
    if not candidate.exists():
        return candidate

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return source_path.with_name(f"{target_name}.decrypted_{timestamp}")


def _write_payload(output_path: Path, metadata: dict[str, Any], ciphertext: bytes) -> Path:
    metadata_bytes = json.dumps(metadata, ensure_ascii=True, indent=2).encode("utf-8")
    output_path.write_bytes(MAGIC + struct.pack(">I", len(metadata_bytes)) + metadata_bytes + ciphertext)
    return output_path


def read_encrypted_payload(source_path: Path) -> tuple[dict[str, Any], bytes]:
    raw_data = source_path.read_bytes()
    if len(raw_data) < len(MAGIC) + 4 or raw_data[: len(MAGIC)] != MAGIC:
        raise ValueError("Le fichier ne correspond pas au format chiffre attendu.")

    metadata_length = struct.unpack(">I", raw_data[len(MAGIC) : len(MAGIC) + 4])[0]
    metadata_start = len(MAGIC) + 4
    metadata_end = metadata_start + metadata_length
    metadata_bytes = raw_data[metadata_start:metadata_end]
    ciphertext = raw_data[metadata_end:]

    try:
        metadata = json.loads(metadata_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Impossible de lire les metadonnees du fichier chiffre.") from exc

    if not isinstance(metadata, dict):
        raise ValueError("Les metadonnees du fichier chiffre sont invalides.")

    return metadata, ciphertext


def inspect_encrypted_file(source_path: Path) -> dict[str, Any]:
    metadata, ciphertext = read_encrypted_payload(source_path)
    return {
        "family": metadata.get("family"),
        "algorithm": metadata.get("algorithm"),
        "source_name": metadata.get("source_name"),
        "created_at_utc": metadata.get("created_at_utc"),
        "ciphertext_size_bytes": len(ciphertext),
        "metadata": metadata,
    }


def _load_history_entries() -> list[dict[str, Any]]:
    if not HISTORY_FILE.exists():
        return []

    try:
        raw_data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(raw_data, list):
        return []

    return [entry for entry in raw_data if isinstance(entry, dict)]


def load_transaction_history(limit: int | None = None) -> list[dict[str, Any]]:
    entries = list(reversed(_load_history_entries()))
    if limit is None:
        return entries
    return entries[:limit]


def load_encryption_history(limit: int | None = None) -> list[dict[str, Any]]:
    return load_transaction_history(limit)


def _append_history_entry(entry: dict[str, Any]) -> None:
    history = _load_history_entries()
    history.append(entry)
    HISTORY_FILE.write_text(json.dumps(history, ensure_ascii=True, indent=2), encoding="utf-8")


def _record_transaction(
    operation: str,
    family: str,
    algorithm: str,
    source_path: Path,
    output_path: Path,
    execution_time_ms: float,
    created_at_utc: str | None = None,
) -> None:
    history_entry = {
        "created_at_utc": created_at_utc or _utc_now(),
        "operation": operation,
        "family": family,
        "algorithm": algorithm,
        "source_name": source_path.name,
        "source_path": str(source_path),
        "source_size_bytes": source_path.stat().st_size,
        "output_name": output_path.name,
        "output_path": str(output_path),
        "execution_time_ms": execution_time_ms,
    }
    _append_history_entry(history_entry)


def _finalize_encryption(
    source_path: Path,
    output_path: Path,
    algorithm: str,
    family: str,
    metadata: dict[str, Any],
    ciphertext: bytes,
    started_at: float,
) -> EncryptionResult:
    _write_payload(output_path, metadata, ciphertext)
    execution_time_ms = round((perf_counter() - started_at) * 1000, 3)
    metadata["execution_time_ms"] = execution_time_ms

    _record_transaction(
        operation="encryption",
        family=family,
        algorithm=metadata.get("algorithm", algorithm),
        source_path=source_path,
        output_path=output_path,
        execution_time_ms=execution_time_ms,
        created_at_utc=metadata.get("created_at_utc"),
    )

    return EncryptionResult(
        output_path=output_path,
        algorithm=algorithm,
        family=family,
        execution_time_ms=execution_time_ms,
        metadata=metadata,
    )


def _finalize_decryption(
    source_path: Path,
    output_path: Path,
    family: str,
    algorithm: str,
    metadata: dict[str, Any],
    plaintext: bytes,
    started_at: float,
) -> DecryptionResult:
    output_path.write_bytes(plaintext)
    execution_time_ms = round((perf_counter() - started_at) * 1000, 3)
    result_metadata = dict(metadata)
    result_metadata["decrypted_at_utc"] = _utc_now()
    result_metadata["execution_time_ms"] = execution_time_ms

    _record_transaction(
        operation="decryption",
        family=family,
        algorithm=algorithm,
        source_path=source_path,
        output_path=output_path,
        execution_time_ms=execution_time_ms,
        created_at_utc=result_metadata["decrypted_at_utc"],
    )

    return DecryptionResult(
        output_path=output_path,
        algorithm=algorithm,
        family=family,
        execution_time_ms=execution_time_ms,
        metadata=result_metadata,
    )


def encrypt_symmetric_file(source_path: Path, algorithm: str, passphrase: str) -> EncryptionResult:
    if not passphrase:
        raise ValueError("Une phrase de passe est requise pour le chiffrement symetrique.")

    started_at = perf_counter()
    plaintext = source_path.read_bytes()
    salt = get_random_bytes(16)
    algorithm_name = algorithm.upper()

    if algorithm_name == "DES":
        iv = get_random_bytes(8)
        key = _derive_key(passphrase, 8, salt)
        ciphertext = DES.new(key, DES.MODE_CBC, iv).encrypt(_pad_pkcs7(plaintext, DES.block_size))
        metadata = {
            "family": "symmetric",
            "algorithm": "DES",
            "mode": "CBC",
            "salt_b64": _encode_b64(salt),
            "iv_b64": _encode_b64(iv),
            "kdf": "PBKDF2-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "source_name": source_path.name,
            "created_at_utc": _utc_now(),
        }
        output_path = _build_encrypted_path(source_path, "des")
    elif algorithm_name == "TRIPLE DES":
        iv = get_random_bytes(8)
        key = _derive_3des_key(passphrase, salt)
        ciphertext = DES3.new(key, DES3.MODE_CBC, iv).encrypt(_pad_pkcs7(plaintext, DES3.block_size))
        metadata = {
            "family": "symmetric",
            "algorithm": "Triple DES",
            "mode": "CBC",
            "salt_b64": _encode_b64(salt),
            "iv_b64": _encode_b64(iv),
            "kdf": "PBKDF2-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "source_name": source_path.name,
            "created_at_utc": _utc_now(),
        }
        output_path = _build_encrypted_path(source_path, "triple_des")
    elif algorithm_name == "AES":
        iv = get_random_bytes(16)
        key = _derive_key(passphrase, 32, salt)
        ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(_pad_pkcs7(plaintext, AES.block_size))
        metadata = {
            "family": "symmetric",
            "algorithm": "AES-256",
            "mode": "CBC",
            "salt_b64": _encode_b64(salt),
            "iv_b64": _encode_b64(iv),
            "kdf": "PBKDF2-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "source_name": source_path.name,
            "created_at_utc": _utc_now(),
        }
        output_path = _build_encrypted_path(source_path, "aes")
    elif algorithm_name == "TWOFISH":
        iv = get_random_bytes(16)
        key = _derive_key(passphrase, 32, salt)
        ciphertext = _twofish_cbc_encrypt(key, iv, plaintext)
        metadata = {
            "family": "symmetric",
            "algorithm": "Twofish-256",
            "mode": "CBC",
            "salt_b64": _encode_b64(salt),
            "iv_b64": _encode_b64(iv),
            "kdf": "PBKDF2-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "source_name": source_path.name,
            "created_at_utc": _utc_now(),
        }
        output_path = _build_encrypted_path(source_path, "twofish")
    else:
        raise ValueError(f"Algorithme symetrique non supporte: {algorithm}")

    return _finalize_encryption(source_path, output_path, algorithm_name, "symmetric", metadata, ciphertext, started_at)


def load_public_key_from_pem(data: bytes):
    return serialization.load_pem_public_key(data)


def load_private_key_from_pem(data: bytes):
    return serialization.load_pem_private_key(data, password=None)


def load_public_key_from_certificate(data: bytes):
    try:
        certificate = x509.load_pem_x509_certificate(data)
    except ValueError:
        certificate = x509.load_der_x509_certificate(data)
    return certificate.public_key(), certificate


def decrypt_symmetric_file(source_path: Path, passphrase: str) -> DecryptionResult:
    if not passphrase:
        raise ValueError("Une phrase de passe est requise pour le dechiffrement symetrique.")

    started_at = perf_counter()
    metadata, ciphertext = read_encrypted_payload(source_path)
    family = str(metadata.get("family", "")).lower()
    if family != "symmetric":
        raise ValueError("Le fichier selectionne n'est pas un fichier chiffre en mode symetrique.")

    algorithm_name = str(metadata.get("algorithm", "")).upper()
    salt = _decode_b64(str(metadata.get("salt_b64", "")))
    iv = _decode_b64(str(metadata.get("iv_b64", "")))

    if algorithm_name == "DES":
        key = _derive_key(passphrase, 8, salt)
        plaintext = DES.new(key, DES.MODE_CBC, iv).decrypt(ciphertext)
        plaintext = _unpad_pkcs7(plaintext, DES.block_size)
    elif algorithm_name == "TRIPLE DES":
        key = _derive_3des_key(passphrase, salt)
        plaintext = DES3.new(key, DES3.MODE_CBC, iv).decrypt(ciphertext)
        plaintext = _unpad_pkcs7(plaintext, DES3.block_size)
    elif algorithm_name == "AES-256":
        key = _derive_key(passphrase, 32, salt)
        plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
        plaintext = _unpad_pkcs7(plaintext, AES.block_size)
    elif algorithm_name == "TWOFISH-256":
        key = _derive_key(passphrase, 32, salt)
        plaintext = _twofish_cbc_decrypt(key, iv, ciphertext)
    else:
        raise ValueError(f"Algorithme symetrique non supporte pour le dechiffrement: {metadata.get('algorithm')}")

    output_path = _build_decrypted_path(source_path, str(metadata.get("source_name", "")) or None)
    return _finalize_decryption(source_path, output_path, "symmetric", str(metadata.get("algorithm", "Symmetric")), metadata, plaintext, started_at)


def decrypt_asymmetric_file(source_path: Path, private_key_data: bytes) -> DecryptionResult:
    started_at = perf_counter()
    metadata, ciphertext = read_encrypted_payload(source_path)
    family = str(metadata.get("family", "")).lower()
    if family != "asymmetric":
        raise ValueError("Le fichier selectionne n'est pas un fichier chiffre en mode asymetrique.")

    private_key = load_private_key_from_pem(private_key_data)
    algorithm_name = str(metadata.get("algorithm", "")).upper()
    nonce = _decode_b64(str(metadata.get("nonce_b64", "")))

    if "wrapped_key_b64" in metadata:
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Une cle privee RSA est requise pour ce fichier.")

        wrapped_key = _decode_b64(str(metadata.get("wrapped_key_b64", "")))
        data_key = private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    elif "ephemeral_public_key_pem" in metadata:
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Une cle privee ECC est requise pour ce fichier.")

        ephemeral_public_key = load_public_key_from_pem(str(metadata.get("ephemeral_public_key_pem", "")).encode("utf-8"))
        if not isinstance(ephemeral_public_key, ec.EllipticCurvePublicKey):
            raise ValueError("La cle publique ephemere embarquee est invalide.")

        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
        data_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"cours-securite-streamlit",
        ).derive(shared_secret)
    else:
        raise ValueError("Le fichier asymetrique ne contient pas les informations necessaires au dechiffrement.")

    plaintext = AESGCM(data_key).decrypt(nonce, ciphertext, None)
    output_path = _build_decrypted_path(source_path, str(metadata.get("source_name", "")) or None)
    return _finalize_decryption(source_path, output_path, "asymmetric", algorithm_name or "Asymmetric", metadata, plaintext, started_at)


def _encrypt_with_rsa_public_key(
    source_path: Path,
    public_key,
    label: str,
    extra_metadata: dict[str, Any] | None = None,
) -> EncryptionResult:
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("La cle fournie n'est pas une cle publique RSA valide.")

    started_at = perf_counter()
    plaintext = source_path.read_bytes()
    data_key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, None)
    wrapped_key = public_key.encrypt(
        data_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    metadata = {
        "family": "asymmetric",
        "algorithm": label,
        "data_cipher": "AES-256-GCM",
        "key_wrap": "RSA-OAEP-SHA256",
        "nonce_b64": _encode_b64(nonce),
        "wrapped_key_b64": _encode_b64(wrapped_key),
        "source_name": source_path.name,
        "created_at_utc": _utc_now(),
    }
    if extra_metadata:
        metadata.update(extra_metadata)
    output_path = _build_encrypted_path(source_path, label.lower().replace(" ", "_"))
    return _finalize_encryption(source_path, output_path, label, "asymmetric", metadata, ciphertext, started_at)


def _encrypt_with_ecc_public_key(
    source_path: Path,
    public_key,
    label: str,
    extra_metadata: dict[str, Any] | None = None,
) -> EncryptionResult:
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("La cle fournie n'est pas une cle publique ECC valide.")

    started_at = perf_counter()
    plaintext = source_path.read_bytes()
    ephemeral_private_key = ec.generate_private_key(public_key.curve)
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)
    data_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"cours-securite-streamlit",
    ).derive(shared_secret)
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, None)
    ephemeral_public_key = ephemeral_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    metadata = {
        "family": "asymmetric",
        "algorithm": label,
        "data_cipher": "AES-256-GCM",
        "key_agreement": "ECDH-HKDF-SHA256",
        "curve": public_key.curve.name,
        "nonce_b64": _encode_b64(nonce),
        "ephemeral_public_key_pem": ephemeral_public_key.decode("utf-8"),
        "source_name": source_path.name,
        "created_at_utc": _utc_now(),
    }
    if extra_metadata:
        metadata.update(extra_metadata)
    output_path = _build_encrypted_path(source_path, label.lower().replace(" ", "_"))
    return _finalize_encryption(source_path, output_path, label, "asymmetric", metadata, ciphertext, started_at)


def encrypt_asymmetric_file(source_path: Path, algorithm: str, key_material: bytes) -> EncryptionResult:
    algorithm_name = algorithm.upper()

    if algorithm_name == "RSA":
        public_key = load_public_key_from_pem(key_material)
        return _encrypt_with_rsa_public_key(source_path, public_key, "RSA")

    if algorithm_name == "ECC":
        public_key = load_public_key_from_pem(key_material)
        return _encrypt_with_ecc_public_key(source_path, public_key, "ECC")

    if algorithm_name == "INFRASTRUCTURE A CLE PUBLIQUE (ICP)":
        public_key, certificate = load_public_key_from_certificate(key_material)
        extra_metadata = {
            "certificate_subject": certificate.subject.rfc4514_string(),
            "certificate_issuer": certificate.issuer.rfc4514_string(),
        }
        if isinstance(public_key, rsa.RSAPublicKey):
            return _encrypt_with_rsa_public_key(source_path, public_key, "ICP RSA", extra_metadata)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            return _encrypt_with_ecc_public_key(source_path, public_key, "ICP ECC", extra_metadata)
        else:
            raise ValueError("Le certificat fourni ne contient ni cle RSA ni cle ECC exploitable.")

    raise ValueError(f"Algorithme asymetrique non supporte: {algorithm}")
