from __future__ import annotations

import json
import os
import struct
from base64 import b64encode
from ctypes import CDLL, POINTER, Structure, c_char_p, c_int, c_uint32, create_string_buffer, pointer
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.util import find_spec
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"CSENC1"
PBKDF2_ITERATIONS = 200_000
CHUNK_SIZE = 64 * 1024


@dataclass(frozen=True)
class EncryptionResult:
    output_path: Path
    algorithm: str
    family: str
    metadata: dict[str, Any]


def list_dump_files(base_dir: Path) -> list[Path]:
    return sorted(base_dir.glob("*.dump"))


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _encode_b64(data: bytes) -> str:
    return b64encode(data).decode("ascii")


def _pad_pkcs7(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


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


def _build_encrypted_path(source_path: Path, suffix: str) -> Path:
    candidate = source_path.with_name(f"{source_path.name}.{suffix}.enc")
    if not candidate.exists():
        return candidate

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return source_path.with_name(f"{source_path.name}.{suffix}_{timestamp}.enc")


def _write_payload(output_path: Path, metadata: dict[str, Any], ciphertext: bytes) -> Path:
    metadata_bytes = json.dumps(metadata, ensure_ascii=True, indent=2).encode("utf-8")
    output_path.write_bytes(MAGIC + struct.pack(">I", len(metadata_bytes)) + metadata_bytes + ciphertext)
    return output_path


def encrypt_symmetric_file(source_path: Path, algorithm: str, passphrase: str) -> EncryptionResult:
    if not passphrase:
        raise ValueError("Une phrase de passe est requise pour le chiffrement symetrique.")

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

    _write_payload(output_path, metadata, ciphertext)
    return EncryptionResult(output_path=output_path, algorithm=algorithm_name, family="symmetric", metadata=metadata)


def load_public_key_from_pem(data: bytes):
    return serialization.load_pem_public_key(data)


def load_public_key_from_certificate(data: bytes):
    try:
        certificate = x509.load_pem_x509_certificate(data)
    except ValueError:
        certificate = x509.load_der_x509_certificate(data)
    return certificate.public_key(), certificate


def _encrypt_with_rsa_public_key(
    source_path: Path,
    public_key,
    label: str,
    extra_metadata: dict[str, Any] | None = None,
) -> EncryptionResult:
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("La cle fournie n'est pas une cle publique RSA valide.")

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
    _write_payload(output_path, metadata, ciphertext)
    return EncryptionResult(output_path=output_path, algorithm=label, family="asymmetric", metadata=metadata)


def _encrypt_with_ecc_public_key(
    source_path: Path,
    public_key,
    label: str,
    extra_metadata: dict[str, Any] | None = None,
) -> EncryptionResult:
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("La cle fournie n'est pas une cle publique ECC valide.")

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
    _write_payload(output_path, metadata, ciphertext)
    return EncryptionResult(output_path=output_path, algorithm=label, family="asymmetric", metadata=metadata)


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
