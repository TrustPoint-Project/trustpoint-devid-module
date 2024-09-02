"""Test data generator module that creates keys and certificate for manual testing of the CLI."""
from pathlib import Path

from tests import generate_certificate, generate_key
from trustpoint_devid_module.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    PrivateKeySerializer,
)
from trustpoint_devid_module.util import SignatureSuite

DATA_DIR = Path(__file__).parent / Path('data')

if __name__ == '__main__':
    if not DATA_DIR.exists():
        DATA_DIR.mkdir()

    keys = []
    for signature_suite in SignatureSuite:
        key = generate_key(signature_suite)
        keys.append((key, signature_suite))
        key_bytes = PrivateKeySerializer(key).as_pkcs8_pem()

        with Path(DATA_DIR / f'{signature_suite.key_type_name}.key').open('wb') as f:
            f.write(key_bytes)

    # TODO(AlexHx8472): Remove code duplication.
    for key, signature_suite in keys:
        root_ca_key = generate_key(signature_suite)
        root_ca_certificate = generate_certificate(
            ca=True,
            public_key=root_ca_key.public_key(),
            private_key=root_ca_key,
            subject_cn=f'{signature_suite.value} Root CA',
            issuer_cn=f'{signature_suite.value} Root CA',
        )

        with Path(DATA_DIR / f'{signature_suite.key_type_name}_root_ca.pem').open('wb') as f:
            f.write(CertificateSerializer(root_ca_certificate).as_pem())

        # TODO(AlexHx8472): Remove code duplication.
        issuing_ca_key = generate_key(signature_suite)
        issuing_ca_certificate = generate_certificate(
            ca=True,
            public_key=issuing_ca_key.public_key(),
            private_key=root_ca_key,
            subject_cn=f'{signature_suite.value} Issuing CA',
            issuer_cn=f'{signature_suite.value} Root CA',
        )

        with Path(DATA_DIR / f'{signature_suite.key_type_name}_issuing_ca.pem').open('wb') as f:
            f.write(CertificateSerializer(issuing_ca_certificate).as_pem())

        ee_certificate = generate_certificate(
            ca=False,
            public_key=key.public_key(),
            private_key=issuing_ca_key,
            subject_cn=f'{signature_suite.value} EE Certificate',
            issuer_cn=f'{signature_suite.value} Issuing CA',
        )

        with Path(DATA_DIR / f'{signature_suite.key_type_name}_ee.pem').open('wb') as f:
            f.write(CertificateSerializer(ee_certificate).as_pem())

        with Path(DATA_DIR / f'{signature_suite.key_type_name}_certificate_chain.pem').open('wb') as f:
            cert_chain = [issuing_ca_certificate, ee_certificate]
            f.write(CertificateCollectionSerializer(cert_chain).as_pem())
