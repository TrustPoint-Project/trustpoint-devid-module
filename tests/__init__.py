"""Tests package for the Trustpoint DevID Module using PyTest."""
from __future__ import annotations

import datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1
from cryptography.x509.oid import NameOID

from trustpoint_devid_module.service_interface import DevIdModule
from trustpoint_devid_module.util import SignatureSuite

if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]
    from _pytest.fixtures import SubRequest

RSA_PUBLIC_EXPONENT = 65537


def generate_key(signature_suite: SignatureSuite) -> PrivateKey:
    """Generates a private key corresponding to the provided signature suite.

    Args:
        signature_suite: The signature suite determining the key type.

    Returns:
        PrivateKey: The generated private key matching the signature suite.
    """
    if signature_suite == SignatureSuite.RSA2048_SHA256_PKCS1_v1_5:
        return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=2048)
    if signature_suite == SignatureSuite.RSA3072_SHA256_PKCS1_v1_5:
        return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=3072)
    if signature_suite == SignatureSuite.RSA4096_SHA256_PKCS1_v1_5:
        return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=4096)
    if signature_suite == SignatureSuite.SECP256R1_SHA256:
        return ec.generate_private_key(SECP256R1())
    if signature_suite == SignatureSuite.SECP384R1_SHA384:
        return ec.generate_private_key(SECP384R1())
    err_msg = 'KeyType is not supported.'
    raise RuntimeError(err_msg)


def generate_certificate(
    ca: bool, public_key: PublicKey, private_key: PrivateKey, subject_cn: str, issuer_cn: str # noqa: FBT001
) -> x509.Certificate:
    """Generates the certificates using the default signature suites.

    Args:
        ca: True, if it shall be a CA certificate. False, otherwise.
        public_key: The public key that will be contained in the certificate.
        private_key: The private key used to sign the certificate.
        subject_cn: The subject CN of the certificate.
        issuer_cn: The issuer CN of the certificate.

    Returns:
        x509.Certificate: The newly generated certificate.
    """
    one_day = datetime.timedelta(365, 0, 0)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
            ]
        )
    )
    builder = builder.issuer_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
            ]
        )
    )
    # TODO(AlexHx8472): If python dependency is changed to >=3.11 use datetime.UTC instead of datetime.timezone.utc
    builder = builder.not_valid_before(datetime.datetime.now(tz=datetime.timezone.utc) - one_day)
    builder = builder.not_valid_after(datetime.datetime.now(tz=datetime.timezone.utc) + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=ca, path_length=None),
        critical=True,
    )
    if isinstance(private_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        algorithm = None
    elif hasattr(private_key, 'curve') and isinstance(private_key.curve, ec.SECP384R1):
        algorithm = hashes.SHA384()
    else:
        algorithm = hashes.SHA256()
    return builder.sign(
        private_key=private_key,
        algorithm=algorithm,
    )


@pytest.fixture
def initialized_tmp_devid_module(tmp_path: Path) -> DevIdModule:
    """Generates an initialized DevIdModule instance with a temporary path.

    Args:
        tmp_path: The temporary working directory path for the DevIdModule instance.

    Returns:
        DevIdModule: The initialized DevIdModule instance.
    """
    tmp_path = tmp_path / Path('trustpoint')

    dev_id_module = DevIdModule(tmp_path)
    dev_id_module.initialize()
    return dev_id_module


@pytest.fixture(scope='session')
def get_private_key_generator() -> callable:
    """Generates a private key for the given signature suite.

    Returns:
        callable: Function that takes a SignatureSuite enum instance and returns a corresponding private key.
    """
    return generate_key


@pytest.fixture(scope='class')
def x509_root_ca_certificate(request: SubRequest) -> x509.Certificate:
    """Generates a root ca certificate for the given signature suite.

    Args:
        request: The request containing a SignatureSuite enum instance to be used to create the root ca certificate.

    Returns:
        x509.Certificate: The root ca certificate
    """
    key_type = request.param

    root_key = generate_key(key_type)
    return generate_certificate(
        ca=True, public_key=root_key.public_key(), private_key=root_key, subject_cn='Root CA', issuer_cn='Root CA'
    )


@pytest.fixture(scope='class')
def x509_credential(request: SubRequest) -> tuple[PrivateKey, x509.Certificate, list[x509.Certificate]]:
    """Generates X.509 credentials for a given signature suite.

    Creates a private key, corresponding certificate and the corresponding certificate chain with the issuing ca
    certificate and the root ca certificate. The first element in the list is the issuing ca certificate.

    Args:
        request: The request containing a SignatureSuite enum instance to be used to create the credential.

    Returns:
        tuple[PrivateKey, x509.Certificate, list[x509.Certificate]]:
            Returns a 3-tuple containing:
            - The private key
            - The ee certificate corresponding to the private key
            - The certificate chain as list with the first element being the issuing ca certificate and the second
              element being the root ca certificate.
    """
    key_type = request.param

    root_key = generate_key(key_type)
    root_ca_cert = generate_certificate(
        ca=True, public_key=root_key.public_key(), private_key=root_key, subject_cn='Root CA', issuer_cn='Root CA'
    )

    issuing_ca_key = generate_key(key_type)
    issuing_ca_cert = generate_certificate(
        ca=True,
        public_key=issuing_ca_key.public_key(),
        private_key=root_key,
        subject_cn='Issuing CA',
        issuer_cn='Root CA',
    )

    ee_key = generate_key(key_type)
    ee_cert = generate_certificate(
        ca=False,
        public_key=ee_key.public_key(),
        private_key=issuing_ca_key,
        subject_cn='EE Cert',
        issuer_cn='Issuing CA',
    )

    return ee_key, ee_cert, [issuing_ca_cert, root_ca_cert]
