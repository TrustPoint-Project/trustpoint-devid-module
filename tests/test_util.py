import pytest

from trustpoint_devid_module.util import KeyType, SignatureSuite
from trustpoint_devid_module.util import PublicKey, PrivateKey


class TestKeyType:

    @pytest.mark.parametrize(
        'public_key_fixture, key_type',
        [(key_type, key_type) for key_type in KeyType],
        indirect=['public_key_fixture'])
    def test_get_key_type_from_public_key(self, public_key_fixture: PublicKey, key_type: KeyType) -> None:
        assert KeyType.get_key_type_from_public_key(public_key_fixture) == key_type

    @pytest.mark.parametrize(
        'private_key_fixture, key_type',
        [(key_type, key_type) for key_type in KeyType],
        indirect=['private_key_fixture'])
    def test_get_key_type_from_private_key(self, private_key_fixture: PrivateKey, key_type: KeyType) -> None:
        assert KeyType.get_key_type_from_private_key(private_key_fixture) == key_type

    @pytest.mark.parametrize(
        'x509_root_ca_certificate, key_type',
        [(key_type, key_type) for key_type in KeyType],
        indirect=['x509_root_ca_certificate'])
    def test_get_key_type_from_certificate(self, x509_root_ca_certificate, key_type: KeyType) -> None:
        assert KeyType.get_key_type_from_certificate(x509_root_ca_certificate) == key_type


class TestSignatureSuite:

    @pytest.mark.parametrize(
        'key_type, signature_suite',
        zip([key_type for key_type in KeyType], [signature_suite for signature_suite in SignatureSuite]))
    def test_get_signature_suite_from_key_type(self, key_type, signature_suite) -> None:
        assert signature_suite.get_signature_suite_from_key_type(key_type) == signature_suite

    @pytest.mark.parametrize(
        'x509_root_ca_certificate, signature_suite',
        zip(
            [key_type for key_type in KeyType],
            [signature_suite for signature_suite in SignatureSuite]),
        indirect=['x509_root_ca_certificate'])
    def test_get_signature_suite_from_certificate(self, x509_root_ca_certificate, signature_suite) -> None:

        assert signature_suite.get_signature_suite_from_certificate(x509_root_ca_certificate) == signature_suite


class TestGetSha256FingerprintAsUpperHexStr:

    def test_get_sha256_fingerprint_as_upper_hex_str(self) -> None:
        # TODO
        pass
