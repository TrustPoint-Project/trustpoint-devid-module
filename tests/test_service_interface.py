from pathlib import Path
import pytest

from tests import private_key_fixture
from trustpoint_devid_module.serializer import PrivateKeySerializer
from trustpoint_devid_module.service_interface import DevIdModule
from trustpoint_devid_module.util import get_sha256_fingerprint_as_upper_hex_str, SignatureSuite, PrivateKey


class TestDevIdModule:

    def test_initialize(self, tmp_path: Path) -> None:
        """Tests if initialize() creates the expected directories and files."""

        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        assert not tmp_path.exists()

        dev_id_module.initialize()

        assert tmp_path.exists()
        assert tmp_path.is_dir()

        assert (tmp_path / Path('inventory.json')).exists()
        assert (tmp_path / Path('inventory.json')).is_file()

        with open(tmp_path / Path('inventory.json'), 'r') as f:
            key_inventory = f.read()
        assert key_inventory == (
            '{"next_key_index":0,"next_certificate_index":0,"devid_keys":{},"devid_certificates":{},'
            '"public_key_fingerprint_mapping":{},"certificate_fingerprint_mapping":{}}')

    def test_purge(self, tmp_path: Path) -> None:
        """Tests if purge() is removing the expected directories and files."""

        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()
        dev_id_module.purge()

        assert not tmp_path.exists()

    @pytest.mark.parametrize(
        'private_key_fixture, signature_suite',
        zip(
            [signature_suite for signature_suite in SignatureSuite],
            [signature_suite for signature_suite in SignatureSuite]),
        indirect=['private_key_fixture'])
    def test_insert_key(self, tmp_path: Path, private_key_fixture: PrivateKey, signature_suite: SignatureSuite) -> None:
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

        assert devid_key.is_enabled == False
        assert devid_key.is_idevid_key == False

        assert devid_key.subject_public_key_info == signature_suite.value.encode()

        assert devid_key.public_key == public_key_bytes
        assert devid_key.private_key == private_key_bytes

        assert dev_id_module.inventory.public_key_fingerprint_mapping.get(public_key_sha256_fingerprint) is not None
        assert dev_id_module.inventory.public_key_fingerprint_mapping[public_key_sha256_fingerprint] == key_index
