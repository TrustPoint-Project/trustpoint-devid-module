from __future__ import annotations

import enum
from pathlib import Path
from hashlib import sha256

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519

from typing import Union

from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.x509.oid import PublicKeyAlgorithmOID, SignatureAlgorithmOID

PublicKey = Union[
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed448.Ed448PublicKey,
    ed25519.Ed25519PublicKey,
]
PrivateKey = Union[
    rsa.RSAPrivateKey,
    ec.EllipticCurvePrivateKey,
    ed448.Ed448PrivateKey,
    ed25519.Ed25519PrivateKey,
]

WORKING_DIR = Path().home() / ".local" / "trustpoint" / "devid-module"


class KeyType(enum.Enum):
    RSA2048 = "RSA2048"
    RSA3072 = "RSA3072"
    RSA4096 = "RSA4096"
    SECP256R1 = "SECP256R1"
    SECP384R1 = "SECP384R1"
    ED448 = "ED448"
    ED25519 = "ED25519"

    @classmethod
    def get_key_type_from_public_key(cls, public_key: PublicKey) -> KeyType:
        if isinstance(public_key, rsa.RSAPublicKey):
            if public_key.key_size == 2048:
                return cls.RSA2048
            elif public_key.key_size == 3072:
                return cls.RSA3072
            elif public_key.key_size == 4096:
                return cls.RSA4096
            else:
                # TODO: Raise UnsupportedRsaKeyLength
                raise ValueError

        if isinstance(public_key, ec.EllipticCurvePublicKey):
            if isinstance(public_key.curve, ec.SECP256R1):
                return cls.SECP256R1
            elif isinstance(public_key.curve, ec.SECP384R1):
                return cls.SECP384R1
            else:
                # TODO: Raise UnsupportedNamedCurveKey
                raise ValueError

        if isinstance(public_key, ed448.Ed448PublicKey):
            return cls.ED448

        if isinstance(public_key, ed25519.Ed25519PublicKey):
            return cls.ED25519

        # TODO: Raise UnsupportedKeyTypeError
        raise ValueError

    @classmethod
    def get_key_type_from_private_key(cls, private_key: PrivateKey) -> KeyType:
        return cls.get_key_type_from_public_key(private_key.public_key())

    @classmethod
    def get_key_type_from_certificate(cls, certificate: x509.Certificate) -> KeyType:
        return cls.get_key_type_from_public_key(certificate.public_key())


class SignatureSuite(enum.Enum):
    """Signature Suites as defined in IEEE 802.1 AR.

    Contains more than the three defined ine IEE 802.1 AR.

    Entries:
        - Verbose Name
        - Public Key Type
        - Private Key Type
        - Key Size
        - Named Curve
        - Hash Algorithm
        - Signature Algorithm OID
        - Signature Algorithm Parameters
    """

    RSA2048_SHA256_PKCS1_v1_5 = (
        "RSA-2048/SHA-256",
        rsa.RSAPublicKey,
        rsa.RSAPrivateKey,
        2048,
        None,
        hashes.SHA256,
        SignatureAlgorithmOID.RSA_WITH_SHA256,
        PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5,
    )

    RSA3072_SHA256_PKCS1_v1_5 = (
        "RSA-3072/SHA-256",
        rsa.RSAPublicKey,
        rsa.RSAPrivateKey,
        3072,
        None,
        hashes.SHA256,
        SignatureAlgorithmOID.RSA_WITH_SHA256,
        PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5,
    )

    RSA4096_SHA256_PKCS1_v1_5 = (
        "RSA-4096/SHA-256",
        rsa.RSAPublicKey,
        rsa.RSAPrivateKey,
        4096,
        None,
        hashes.SHA256,
        SignatureAlgorithmOID.RSA_WITH_SHA256,
        PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5,
    )

    SECP256R1_SHA256 = (
        "ECDSA P-256/SHA-256",
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        256,
        ec.SECP256R1,
        hashes.SHA256,
        SignatureAlgorithmOID.ECDSA_WITH_SHA256,
        PublicKeyAlgorithmOID.EC_PUBLIC_KEY,
    )

    SECP384R1_SHA384 = (
        "ECDSA P-384/SHA-384",
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        384,
        ec.SECP384R1,
        hashes.SHA384,
        SignatureAlgorithmOID.ECDSA_WITH_SHA256,
        PublicKeyAlgorithmOID.EC_PUBLIC_KEY,
    )

    ED448 = (
        "ED448",
        ed448.Ed448PublicKey,
        ed448.Ed448PrivateKey,
        456,
        None,
        None,
        SignatureAlgorithmOID.ED448,
        PublicKeyAlgorithmOID.ED448,
    )

    ED25519 = (
        "ED25519",
        ed25519.Ed25519PublicKey,
        ed25519.Ed25519PrivateKey,
        256,
        None,
        None,
        SignatureAlgorithmOID.ED25519,
        PublicKeyAlgorithmOID.ED25519,
    )

    def __new__(
        cls,
        verbose_name: str,
        public_key_type: type[PublicKey],
        private_key_type: type[PrivateKey],
        key_size: int,
        named_curve_type: type[ec.EllipticCurve] | None,
        hash_algorithm: type[HashAlgorithm] | None,
        signature_algorithm_oid: SignatureAlgorithmOID,
        public_key_algorithm_oid: PublicKeyAlgorithmOID,
    ) -> object:
        obj = object.__new__(cls)
        obj._value_ = verbose_name
        obj.verbose_name = verbose_name
        obj.public_key_type = public_key_type
        obj.private_key_type = private_key_type
        obj.key_size = key_size
        obj.named_curve_type = named_curve_type
        obj.hash_algorithm = hash_algorithm
        obj.signature_algorithm_oid = signature_algorithm_oid
        obj.public_key_algorithm_oid = public_key_algorithm_oid
        return obj

    @classmethod
    def get_signature_suite_from_key_type(cls, key_type: KeyType) -> SignatureSuite:
        if key_type == KeyType.RSA2048:
            return cls.RSA2048_SHA256_PKCS1_v1_5
        elif key_type == KeyType.RSA3072:
            return cls.RSA3072_SHA256_PKCS1_v1_5
        elif key_type == KeyType.RSA4096:
            return cls.RSA4096_SHA256_PKCS1_v1_5
        elif key_type == KeyType.SECP256R1:
            return cls.SECP256R1_SHA256
        elif key_type == KeyType.SECP384R1:
            return cls.SECP384R1_SHA384
        elif key_type == KeyType.ED448:
            return cls.ED448
        elif key_type == KeyType.ED25519:
            return cls.ED25519

        # TODO: raise UnsupportedKeyError
        raise ValueError

    @classmethod
    def get_signature_suite_from_certificate(
        cls, certificate: x509.Certificate
    ) -> SignatureSuite:
        # TODO: Remove duplicate code, may integrate KeyType enum in SignatureSuite enum
        key_type = KeyType.get_key_type_from_public_key(certificate.public_key())
        print(key_type)
        if (
            key_type == KeyType.RSA2048
            or key_type == KeyType.RSA3072
            or key_type == KeyType.RSA4096
        ):
            if (
                certificate.signature_algorithm_oid
                != SignatureAlgorithmOID.RSA_WITH_SHA256
            ):
                raise ValueError
            if (
                certificate.public_key_algorithm_oid
                != PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
            ):
                raise ValueError

            if key_type == KeyType.RSA2048:
                return SignatureSuite.RSA2048_SHA256_PKCS1_v1_5
            if key_type == KeyType.RSA3072:
                return SignatureSuite.RSA3072_SHA256_PKCS1_v1_5
            if key_type == KeyType.RSA4096:
                return SignatureSuite.RSA4096_SHA256_PKCS1_v1_5

        if key_type == KeyType.SECP256R1:
            if (
                certificate.signature_algorithm_oid
                != SignatureAlgorithmOID.ECDSA_WITH_SHA256
            ):
                raise ValueError
            if (
                certificate.public_key_algorithm_oid
                != PublicKeyAlgorithmOID.EC_PUBLIC_KEY
            ):
                raise ValueError
            return SignatureSuite.SECP256R1_SHA256

        if key_type == KeyType.SECP384R1:
            if (
                certificate.signature_algorithm_oid
                != SignatureAlgorithmOID.ECDSA_WITH_SHA384
            ):
                raise ValueError
            if (
                certificate.public_key_algorithm_oid
                != PublicKeyAlgorithmOID.EC_PUBLIC_KEY
            ):
                raise ValueError
            return SignatureSuite.SECP384R1_SHA384

        if key_type == KeyType.ED448:
            if certificate.signature_algorithm_oid != SignatureAlgorithmOID.ED448:
                raise ValueError
            if certificate.public_key_algorithm_oid != PublicKeyAlgorithmOID.ED448:
                raise ValueError
            return SignatureSuite.ED448

        if key_type == KeyType.ED25519:
            if certificate.signature_algorithm_oid != SignatureAlgorithmOID.ED25519:
                raise ValueError
            if certificate.public_key_algorithm_oid != PublicKeyAlgorithmOID.ED25519:
                raise ValueError
            return SignatureSuite.ED25519


def get_sha256_fingerprint_as_upper_hex_str(data: bytes) -> str:
    hash_builder = sha256()
    hash_builder.update(data)
    return hash_builder.hexdigest().upper()
