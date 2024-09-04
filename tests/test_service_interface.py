"""Service interface tests."""

from pathlib import Path

import random
import pytest

from tests import private_key_fixture, x509_credential  # noqa: F401
from trustpoint_devid_module.exceptions import DevIdKeyExistsError, CorruptedKeyDataError, DevIdCertificateExistsError, \
    CorruptedCertificateDataError, DevIdCertificateChainExistsError
from trustpoint_devid_module.serializer import PrivateKeySerializer, CertificateSerializer, \
    CertificateCollectionSerializer
from trustpoint_devid_module.service_interface import DevIdModule
from trustpoint_devid_module.util import PrivateKey, SignatureSuite, get_sha256_fingerprint_as_upper_hex_str


class TestDevIdModule:
    """Tests the DevIdModule class."""

    def test_initialize(self, tmp_path: Path) -> None:
        """Tests if initialize() creates the expected directories and files.

        Args:
            tmp_path: The temporary path used as working directory for the DevID Module.
        """
        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        assert not tmp_path.exists()

        dev_id_module.initialize()

        assert tmp_path.exists()
        assert tmp_path.is_dir()

        assert (tmp_path / Path('inventory.json')).exists()
        assert (tmp_path / Path('inventory.json')).is_file()

        with Path(tmp_path / Path('inventory.json')).open('r') as f:
            key_inventory = f.read()
        assert key_inventory == (
            '{"next_key_index":0,"next_certificate_index":0,"devid_keys":{},"devid_certificates":{},'
            '"public_key_fingerprint_mapping":{},"certificate_fingerprint_mapping":{}}'
        )

    def test_purge(self, tmp_path: Path) -> None:
        """Tests if purge() is removing the expected directories and files."""
        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()
        dev_id_module.purge()

        assert not tmp_path.exists()

    @pytest.mark.parametrize(
        'private_key_fixture',
        list(SignatureSuite),
        indirect=['private_key_fixture'],
    )
    def test_insert_ldevid_key(
        self,
        tmp_path: Path,
        private_key_fixture: PrivateKey,    # noqa: F811
    ) -> None:
        """Tests the insertion of private LDevID keys."""
        ee_private_key = private_key_fixture
        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()

        # get bytes in DER format, sha256 fingerprints and file names of both the private and public key
        private_key_bytes = PrivateKeySerializer(ee_private_key).as_pkcs8_pem()
        public_key_bytes = PrivateKeySerializer(ee_private_key).public_key_serializer.as_pem()
        public_key_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(public_key_bytes)

        key_index = dev_id_module.insert_ldevid_key(ee_private_key)

        assert dev_id_module.inventory.devid_keys[key_index]
        devid_key = dev_id_module.inventory.devid_keys[key_index]

        assert devid_key.key_index == key_index
        assert not devid_key.certificate_indices

        assert not devid_key.is_enabled
        assert not devid_key.is_idevid_key

        assert devid_key.public_key == public_key_bytes
        assert devid_key.private_key == private_key_bytes

        assert dev_id_module.inventory.public_key_fingerprint_mapping.get(public_key_sha256_fingerprint) is not None
        assert dev_id_module.inventory.public_key_fingerprint_mapping[public_key_sha256_fingerprint] == key_index

    @pytest.mark.parametrize(
        'private_key_fixture',
        list(SignatureSuite),
        indirect=['private_key_fixture'],
    )
    def test_enable_ldevid_key(
            self,
            tmp_path: Path,
            private_key_fixture: PrivateKey,  # noqa: F811
    ) -> None:
        """Tests the insertion of private LDevID keys."""
        ee_private_key = private_key_fixture
        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()

        key_index = dev_id_module.insert_ldevid_key(ee_private_key)
        dev_id_module.enable_devid_key(key_index)
        assert dev_id_module.inventory.devid_keys[key_index].is_enabled is True

        dev_id_module.enable_devid_key(key_index)
        assert dev_id_module.inventory.devid_keys[key_index].is_enabled is True

    @pytest.mark.parametrize(
        'private_key_fixture',
        list(SignatureSuite),
        indirect=['private_key_fixture'],
    )
    def test_disable_ldevid_key(
            self,
            tmp_path: Path,
            private_key_fixture: PrivateKey,  # noqa: F811
    ) -> None:
        """Tests the insertion of private LDevID keys."""
        ee_private_key = private_key_fixture
        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()

        key_index = dev_id_module.insert_ldevid_key(ee_private_key)
        dev_id_module.enable_devid_key(key_index)
        assert dev_id_module.inventory.devid_keys[key_index].is_enabled is True

        dev_id_module.disable_devid_key(key_index)
        assert dev_id_module.inventory.devid_keys[key_index].is_enabled is False

        dev_id_module.disable_devid_key(key_index)
        assert dev_id_module.inventory.devid_keys[key_index].is_enabled is False

    @pytest.mark.parametrize(
        'private_key_fixture',
        list(SignatureSuite),
        indirect=['private_key_fixture'],
    )
    def test_insert_existing_ldevid_key(
        self,
        tmp_path: Path,
        private_key_fixture: PrivateKey,    # noqa: F811
    ) -> None:
        """Tests the insertion of an already existing private LDevID keys."""
        ee_private_key = private_key_fixture
        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()

        dev_id_module.insert_ldevid_key(ee_private_key)

        with pytest.raises(DevIdKeyExistsError):
            dev_id_module.insert_ldevid_key(ee_private_key)


    @pytest.mark.parametrize(
        'private_key_fixture',
        list(SignatureSuite),
        indirect=['private_key_fixture'],
    )
    def test_insert_random_bytes_as_ldevid_key(
            self,
            tmp_path: Path,
            private_key_fixture: PrivateKey,  # noqa: F811
    ) -> None:
        """Tests the insertion of random bytes as LDevID key."""
        ee_private_key = random.randbytes(1024)
        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()

        with pytest.raises(CorruptedKeyDataError):
            dev_id_module.insert_ldevid_key(ee_private_key)

    @pytest.mark.parametrize(
        'x509_credential',
        list(SignatureSuite),
        indirect=['x509_credential'],
    )
    def test_insert_ldevid_certificate(
            self,
            tmp_path: Path,
            x509_credential: PrivateKey,  # noqa: F811
    ) -> None:
        """Tests the insertion of private LDevID keys."""
        private_key, certificate, _ = x509_credential
        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()

        key_index = dev_id_module.insert_ldevid_key(private_key)
        cert_index = dev_id_module.insert_ldevid_certificate(certificate)

        certificate_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(
            CertificateSerializer(certificate).as_pem())

        assert certificate_sha256_fingerprint in dev_id_module.inventory.certificate_fingerprint_mapping
        assert cert_index == dev_id_module.inventory.certificate_fingerprint_mapping[certificate_sha256_fingerprint]
        assert dev_id_module.inventory.devid_certificates[cert_index].is_enabled is False
        assert dev_id_module.inventory.devid_certificates[cert_index].key_index == key_index

    @pytest.mark.parametrize(
        'x509_credential',
        list(SignatureSuite),
        indirect=['x509_credential'],
    )
    def test_enable_ldevid_certificate(
            self,
            tmp_path: Path,
            x509_credential: PrivateKey,  # noqa: F811
    ) -> None:
        """Tests the insertion of private LDevID keys."""
        private_key, certificate, _ = x509_credential
        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()

        dev_id_module.insert_ldevid_key(private_key)
        cert_index = dev_id_module.insert_ldevid_certificate(certificate)

        dev_id_module.enable_devid_certificate(cert_index)
        assert dev_id_module.inventory.devid_certificates[cert_index].is_enabled is True

        dev_id_module.enable_devid_certificate(cert_index)
        assert dev_id_module.inventory.devid_certificates[cert_index].is_enabled is True

    @pytest.mark.parametrize(
        'x509_credential',
        list(SignatureSuite),
        indirect=['x509_credential'],
    )
    def test_disable_ldevid_certificate(
            self,
            tmp_path: Path,
            x509_credential: PrivateKey,  # noqa: F811
    ) -> None:
        """Tests the insertion of private LDevID keys."""
        private_key, certificate, _ = x509_credential
        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()

        dev_id_module.insert_ldevid_key(private_key)
        cert_index = dev_id_module.insert_ldevid_certificate(certificate)

        dev_id_module.enable_devid_certificate(cert_index)
        assert dev_id_module.inventory.devid_certificates[cert_index].is_enabled is True

        dev_id_module.disable_devid_certificate(cert_index)
        assert dev_id_module.inventory.devid_certificates[cert_index].is_enabled is False

        dev_id_module.disable_devid_certificate(cert_index)
        assert dev_id_module.inventory.devid_certificates[cert_index].is_enabled is False

    @pytest.mark.parametrize(
        'x509_credential',
        list(SignatureSuite),
        indirect=['x509_credential'],
    )
    def test_insert_ldevid_certificate(
            self,
            tmp_path: Path,
            x509_credential: PrivateKey,  # noqa: F811
    ) -> None:
        """Tests the insertion of private LDevID keys."""
        private_key, certificate, _ = x509_credential
        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()

        key_index = dev_id_module.insert_ldevid_key(private_key)
        cert_index = dev_id_module.insert_ldevid_certificate(certificate)


        certificate_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(
            CertificateSerializer(certificate).as_pem())

        inventory = dev_id_module.inventory
        assert certificate_sha256_fingerprint in inventory.certificate_fingerprint_mapping
        assert cert_index == inventory.certificate_fingerprint_mapping[certificate_sha256_fingerprint]
        assert inventory.devid_certificates[cert_index].key_index == key_index
        assert inventory.devid_keys[key_index].key_index == key_index
        assert inventory.devid_keys[key_index].certificate_indices == [cert_index]

    @pytest.mark.parametrize(
        'x509_credential',
        list(SignatureSuite),
        indirect=['x509_credential'],
    )
    def test_insert_existing_ldevid_certificate(
            self,
            tmp_path: Path,
            x509_credential: PrivateKey,  # noqa: F811
    ) -> None:
        """Tests the insertion of private LDevID keys."""
        private_key, certificate, _ = x509_credential
        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()

        dev_id_module.insert_ldevid_key(private_key)
        dev_id_module.insert_ldevid_certificate(certificate)

        with pytest.raises(DevIdCertificateExistsError):
            dev_id_module.insert_ldevid_certificate(certificate)

    @pytest.mark.parametrize(
        'private_key_fixture',
        list(SignatureSuite),
        indirect=['private_key_fixture'],
    )
    def test_insert_random_bytes_as_ldevid_certificate(
            self,
            tmp_path: Path,
            private_key_fixture: PrivateKey,  # noqa: F811
    ) -> None:
        """Tests the insertion of random bytes as LDevID key."""
        random_bytes = random.randbytes(1024)
        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()

        with pytest.raises(CorruptedCertificateDataError):
            dev_id_module.insert_ldevid_certificate(random_bytes)

    @pytest.mark.parametrize(
        'x509_credential',
        list(SignatureSuite),
        indirect=['x509_credential'],
    )
    def test_insert_ldevid_certificate_chain(
            self,
            tmp_path: Path,
            x509_credential: PrivateKey,  # noqa: F811
    ) -> None:
        """Tests the insertion of private LDevID keys."""
        private_key, certificate, certificate_chain = x509_credential
        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()

        key_index = dev_id_module.insert_ldevid_key(private_key)
        cert_index = dev_id_module.insert_ldevid_certificate(certificate)
        dev_id_module.enable_devid_key(key_index)
        dev_id_module.enable_devid_certificate(cert_index)

        assert dev_id_module.inventory.devid_certificates[cert_index].certificate_chain == []
        cert_index_from_chain = dev_id_module.insert_ldevid_certificate_chain(cert_index, certificate_chain)
        pem_cert_list = CertificateCollectionSerializer(certificate_chain).as_pem_list()
        assert dev_id_module.inventory.devid_certificates[cert_index].certificate_chain == pem_cert_list
        assert cert_index == cert_index_from_chain

    @pytest.mark.parametrize(
        'x509_credential',
        list(SignatureSuite),
        indirect=['x509_credential'],
    )
    def test_insert_ldevid_certificate_chain_if_devid_certificate_already_contains_a_certificate_chain(
            self,
            tmp_path: Path,
            x509_credential: PrivateKey,  # noqa: F811
    ) -> None:
        """Tests the insertion of private LDevID keys."""
        private_key, certificate, certificate_chain = x509_credential
        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()

        key_index = dev_id_module.insert_ldevid_key(private_key)
        cert_index = dev_id_module.insert_ldevid_certificate(certificate)
        dev_id_module.enable_devid_key(key_index)
        dev_id_module.enable_devid_certificate(cert_index)

        dev_id_module.insert_ldevid_certificate_chain(cert_index, certificate_chain)

        with pytest.raises(DevIdCertificateChainExistsError):
            dev_id_module.insert_ldevid_certificate_chain(cert_index, certificate_chain)

    @pytest.mark.parametrize(
        'x509_credential',
        list(SignatureSuite),
        indirect=['x509_credential'],
    )
    def test_insert_random_bytes_as_ldevid_certificate_chain(
            self,
            tmp_path: Path,
            x509_credential: PrivateKey,  # noqa: F811
    ) -> None:
        """Tests the insertion of private LDevID keys."""
        private_key, certificate, certificate_chain = x509_credential
        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()

        key_index = dev_id_module.insert_ldevid_key(private_key)
        cert_index = dev_id_module.insert_ldevid_certificate(certificate)
        dev_id_module.enable_devid_key(key_index)
        dev_id_module.enable_devid_certificate(cert_index)

        assert dev_id_module.inventory.devid_certificates[cert_index].certificate_chain == []
        cert_index_from_chain = dev_id_module.insert_ldevid_certificate_chain(cert_index, certificate_chain)
        pem_cert_list = CertificateCollectionSerializer(certificate_chain).as_pem_list()
        assert dev_id_module.inventory.devid_certificates[cert_index].certificate_chain == pem_cert_list
        assert cert_index == cert_index_from_chain


    # @pytest.mark.parametrize(
    #     'x509_credential',
    #     list(SignatureSuite),
    #     indirect=['x509_credential'],
    # )
    # def test_insert_existing_ldevid_certificate(
    #         self,
    #         tmp_path: Path,
    #         x509_credential: PrivateKey,  # noqa: F811
    # ) -> None:
    #     """Tests the insertion of private LDevID keys."""
    #     private_key, certificate, _ = x509_credential
    #     tmp_path = tmp_path / Path('trustpoint')
    #
    #     dev_id_module = DevIdModule(tmp_path)
    #     dev_id_module.initialize()
    #
    #     dev_id_module.insert_ldevid_key(private_key)
    #     dev_id_module.insert_ldevid_certificate(certificate)
    #
    #     with pytest.raises(DevIdCertificateExistsError):
    #         dev_id_module.insert_ldevid_certificate(certificate)
    #
    # @pytest.mark.parametrize(
    #     'private_key_fixture',
    #     list(SignatureSuite),
    #     indirect=['private_key_fixture'],
    # )
    # def test_insert_random_bytes_as_ldevid_certificate(
    #         self,
    #         tmp_path: Path,
    #         private_key_fixture: PrivateKey,  # noqa: F811
    # ) -> None:
    #     """Tests the insertion of random bytes as LDevID key."""
    #     random_bytes = random.randbytes(1024)
    #     tmp_path = tmp_path / Path('trustpoint')
    #
    #     dev_id_module = DevIdModule(tmp_path)
    #     dev_id_module.initialize()
    #
    #     with pytest.raises(CorruptedCertificateDataError):
    #         dev_id_module.insert_ldevid_certificate(random_bytes)