from __future__ import annotations

import pytest
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519
import datetime
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1

from typing import TYPE_CHECKING

from trustpoint_devid_module.service_interface import DevIdModule
from trustpoint_devid_module.util import SignatureSuite

if TYPE_CHECKING:
    from typing import Union
    PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
    PublicKey = Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]

RSA_PUBLIC_EXPONENT = 65537

def generate_key(signature_suite: SignatureSuite) -> PrivateKey:
    if signature_suite == SignatureSuite.RSA2048_SHA256_PKCS1_v1_5:
        return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=2048)
    elif signature_suite == SignatureSuite.RSA3072_SHA256_PKCS1_v1_5:
        return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=3072)
    elif signature_suite == SignatureSuite.RSA4096_SHA256_PKCS1_v1_5:
        return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=4096)
    elif signature_suite == SignatureSuite.SECP256R1_SHA256:
        return ec.generate_private_key(SECP256R1())
    elif signature_suite == SignatureSuite.SECP384R1_SHA384:
        return ec.generate_private_key(SECP384R1())
    else:
        err_msg = 'KeyType is not supported.'
        raise RuntimeError(err_msg)

def generate_certificate(ca: bool, public_key: PublicKey, private_key: PrivateKey, subject_cn: str, issuer_cn: str
                ) -> x509.Certificate:
    """Generates the certificates using the default signature suites."""
    one_day = datetime.timedelta(365, 0, 0)
    public_key = public_key
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
    ]))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=ca, path_length=None), critical=True,
    )
    if isinstance(private_key, ed448.Ed448PrivateKey) or isinstance(private_key, ed25519.Ed25519PrivateKey):
        algorithm = None
    elif isinstance(private_key, ec.EllipticCurvePrivateKey) and isinstance(private_key.curve, ec.SECP384R1):
        algorithm = hashes.SHA384()
    else:
        algorithm = hashes.SHA256()
    return builder.sign(
        private_key=private_key, algorithm=algorithm,
    )

@pytest.fixture(scope='function')
def initialized_tmp_devid_module(request, tmp_path: Path) -> DevIdModule:
    tmp_path = tmp_path / Path('trustpoint')

    dev_id_module = DevIdModule(tmp_path)
    dev_id_module.initialize()
    return dev_id_module

@pytest.fixture(scope='class')
def private_key_fixture(request) -> PrivateKey:
    return generate_key(request.param)

@pytest.fixture(scope='class')
def public_key_fixture(request) -> PublicKey:
    return generate_key(request.param).public_key()

@pytest.fixture(scope='class')
def x509_root_ca_certificate(request) -> x509.Certificate:
    key_type = request.param

    root_key = generate_key(key_type)
    return generate_certificate(
        ca=True,
        public_key=root_key.public_key(),
        private_key=root_key,
        subject_cn='Root CA',
        issuer_cn='Root CA')

@pytest.fixture(scope='class')
def x509_credential(request) -> tuple[PrivateKey, x509.Certificate, list[x509.Certificate]]:
    key_type = request.param

    root_key = generate_key(key_type)
    root_ca_cert = generate_certificate(
        ca=True,
        public_key=root_key.public_key(),
        private_key=root_key,
        subject_cn='Root CA',
        issuer_cn='Root CA')

    issuing_ca_key = generate_key(key_type)
    issuing_ca_cert = generate_certificate(
        ca=True,
        public_key=issuing_ca_key.public_key(),
        private_key=root_key,
        subject_cn='Issuing CA',
        issuer_cn='Root CA'
    )

    ee_key = generate_key(key_type)
    ee_cert = generate_certificate(
        ca=False,
        public_key=ee_key.public_key(),
        private_key=issuing_ca_key,
        subject_cn='EE Cert',
        issuer_cn='Issuing CA'
    )

    return ee_key, ee_cert, [issuing_ca_cert, root_ca_cert]
