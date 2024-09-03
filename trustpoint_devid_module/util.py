"""The Util module contains some helper classes and functions."""
from __future__ import annotations

import enum
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
from cryptography.x509.oid import PublicKeyAlgorithmOID, SignatureAlgorithmOID

from trustpoint_devid_module.exceptions import SignatureSuiteNotSupportedError

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.hashes import HashAlgorithm

    from trustpoint_devid_module.serializer import CertificateSerializer, PrivateKeySerializer, PublicKeySerializer

PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]
PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]

WORKING_DIR = Path().home() / '.local' / 'trustpoint' / 'devid-module'

RSA_2048_KEY_SIZE = 2048
RSA_3072_KEY_SIZE = 3072
RSA_4096_KEY_SIZE = 4096
SECP256R1_KEY_SIZE = 256
SECP384R1_KEY_SIZE = 384


# TODO(AlexHx8472): Rework to use proper Subject Public Key Info Bytes
class SignatureSuite(enum.Enum):
    """Signature Suites as defined in IEEE 802.1 AR.

    Contains more than the three defined ine IEE 802.1 AR.

    Entries:
        - Verbose Name
        - Public Key Type
        - Private Key Type
        - Key Size
        - Padding
        - Named Curve
        - Hash Algorithm
        - Signature Algorithm OID
        - Signature Algorithm Parameters
    """

    RSA2048_SHA256_PKCS1_v1_5 = (
        'RSA-2048/SHA-256',
        rsa.RSAPublicKey,
        rsa.RSAPrivateKey,
        RSA_2048_KEY_SIZE,
        crypto_padding.PKCS1v15,
        None,
        hashes.SHA256,
        SignatureAlgorithmOID.RSA_WITH_SHA256,
        PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5,
        'rsa_2048',
    )

    RSA3072_SHA256_PKCS1_v1_5 = (
        'RSA-3072/SHA-256',
        rsa.RSAPublicKey,
        rsa.RSAPrivateKey,
        RSA_3072_KEY_SIZE,
        crypto_padding.PKCS1v15,
        None,
        hashes.SHA256,
        SignatureAlgorithmOID.RSA_WITH_SHA256,
        PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5,
        'rsa_3072',
    )

    RSA4096_SHA256_PKCS1_v1_5 = (
        'RSA-4096/SHA-256',
        rsa.RSAPublicKey,
        rsa.RSAPrivateKey,
        RSA_4096_KEY_SIZE,
        crypto_padding.PKCS1v15,
        None,
        hashes.SHA256,
        SignatureAlgorithmOID.RSA_WITH_SHA256,
        PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5,
        'rsa_4096',
    )

    SECP256R1_SHA256 = (
        'ECDSA P-256/SHA-256',
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        SECP256R1_KEY_SIZE,
        None,
        ec.SECP256R1,
        hashes.SHA256,
        SignatureAlgorithmOID.ECDSA_WITH_SHA256,
        PublicKeyAlgorithmOID.EC_PUBLIC_KEY,
        'secp256r1',
    )

    SECP384R1_SHA384 = (
        'ECDSA P-384/SHA-384',
        ec.EllipticCurvePublicKey,
        ec.EllipticCurvePrivateKey,
        SECP384R1_KEY_SIZE,
        None,
        ec.SECP384R1,
        hashes.SHA384,
        SignatureAlgorithmOID.ECDSA_WITH_SHA384,
        PublicKeyAlgorithmOID.EC_PUBLIC_KEY,
        'secp384r1',
    )

    def __new__(    # noqa: PLR0913
        cls,
        verbose_name: str,
        public_key_type: type[PublicKey],
        private_key_type: type[PrivateKey],
        key_size: int,
        padding: None | crypto_padding.AsymmetricPadding,
        named_curve_type: type[ec.EllipticCurve] | None,
        hash_algorithm: type[HashAlgorithm] | None,
        signature_algorithm_oid: SignatureAlgorithmOID,
        public_key_algorithm_oid: PublicKeyAlgorithmOID,
        key_type_name: str,
    ) -> object:
        """Adds attributes to the enum class."""
        obj = object.__new__(cls)
        obj._value_ = verbose_name
        obj.verbose_name = verbose_name
        obj.public_key_type = public_key_type
        obj.private_key_type = private_key_type
        obj.key_size = key_size
        obj.padding = padding
        obj.named_curve_type = named_curve_type
        obj.hash_algorithm = hash_algorithm
        obj.signature_algorithm_oid = signature_algorithm_oid
        obj.public_key_algorithm_oid = public_key_algorithm_oid
        obj.key_type_name = key_type_name
        return obj

    @classmethod
    def get_signature_suite_from_public_key_type(cls, public_key: PublicKeySerializer) -> SignatureSuite:
        """Returns the SignatureSuite enum corresponding to the provided public key.

        Args:
            public_key: The public key to get a matching SignatureSuite for.

        Returns:
            SignatureSuite: The matching SignatureSuite enum corresponding to the provided public key.
        """
        public_key = public_key.as_crypto()

        if isinstance(public_key, rsa.RSAPublicKey):
            if public_key.key_size == RSA_2048_KEY_SIZE:
                return cls.RSA2048_SHA256_PKCS1_v1_5
            if public_key.key_size == RSA_3072_KEY_SIZE:
                return cls.RSA3072_SHA256_PKCS1_v1_5
            if public_key.key_size == RSA_4096_KEY_SIZE:
                return cls.RSA4096_SHA256_PKCS1_v1_5
            raise ValueError

        if isinstance(public_key, ec.EllipticCurvePublicKey):
            if isinstance(public_key.curve, ec.SECP256R1):
                return cls.SECP256R1_SHA256
            if isinstance(public_key.curve, ec.SECP384R1):
                return cls.SECP384R1_SHA384
            raise ValueError

        raise ValueError

    @classmethod
    def get_signature_suite_from_private_key_type(cls, private_key: PrivateKeySerializer) -> SignatureSuite:
        """Returns the SignatureSuite enum corresponding to the provided private key.

        Args:
            private_key: The private key to get a matching SignatureSuite for.

        Returns:
            SignatureSuite: The matching SignatureSuite enum corresponding to the provided private key.
        """
        return cls.get_signature_suite_from_public_key_type(private_key.public_key_serializer)

    @classmethod
    def get_signature_suite_from_certificate(cls, certificate: CertificateSerializer) -> SignatureSuite:
        """Returns the SignatureSuite enum corresponding to the provided certificate.

        Args:
            certificate: The certificate to get a matching SignatureSuite for.

        Returns:
            SignatureSuite: The matching SignatureSuite enum corresponding to the provided certificate.

        Raises:
            SignatureSuiteNotSupported: If the signature suite is not supported.
        """
        signature_suite = cls.get_signature_suite_from_public_key_type(certificate.public_key_serializer)
        if certificate.as_crypto().signature_algorithm_oid != signature_suite.signature_algorithm_oid:
            raise SignatureSuiteNotSupportedError
        return signature_suite


def get_sha256_fingerprint_as_upper_hex_str(data: bytes) -> str:
    """Returns the SHA256 fingerprint of the provided data (bytes) as an upper hex string.

    Args:
        data: The bytes to hash with the SHA256 algorithm.

    Returns:
        SHA256 fingerprint of the provided data (bytes) as an upper hex string.
    """
    hash_builder = sha256()
    hash_builder.update(data)
    return hash_builder.hexdigest().upper()
