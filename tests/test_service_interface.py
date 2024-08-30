from pathlib import Path

from trustpoint_devid_module.schema import KeyInventory
from trustpoint_devid_module.serializer import PrivateKeySerializer
from trustpoint_devid_module.service_interface import DevIdModule
from trustpoint_devid_module.util import get_sha256_fingerprint_as_upper_hex_str


class TestDevIdModule:

    def test_initialize(self, tmp_path: Path) -> None:
        """Tests if initialize() creates the expected directories and files."""

        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        assert not tmp_path.exists()

        dev_id_module.initialize()

        assert tmp_path.exists()
        assert tmp_path.is_dir()

        assert (tmp_path / Path('key_inventory.json')).exists()
        assert (tmp_path / Path('key_inventory.json')).is_file()

        with open(tmp_path / Path('key_inventory.json'), 'r') as f:
            key_inventory = f.read()
        assert key_inventory == '{"next_available_index":0,"keys":[]}'

        assert (tmp_path / Path('certificate_inventory.json')).exists()
        assert (tmp_path / Path('certificate_inventory.json')).is_file()

        with open(tmp_path / Path('certificate_inventory.json'), 'r') as f:
            certificate_inventory = f.read()
        assert certificate_inventory == '{"next_available_index":0,"certificates":[]}'

    def test_purge(self, tmp_path: Path) -> None:
        """Tests if purge() is removing the expected directories and files."""

        tmp_path = tmp_path / Path('trustpoint')

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()
        dev_id_module.purge()

        assert not tmp_path.exists()

    def test_insert_key(self, tmp_path: Path, x509_credential) -> None:
        """Tests the insertion of private LDevID keys."""

        ee_private_key, key_type, _, _ = x509_credential
        tmp_path = tmp_path / Path('trustpoint')

        # get bytes in DER format, sha256 fingerprints and file names of both the private and public key
        private_key_bytes = PrivateKeySerializer(ee_private_key).as_pkcs8_der()
        private_key_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(private_key_bytes)
        private_key_file_name = f'private_key_{private_key_sha256_fingerprint}.der'

        public_key_bytes = PrivateKeySerializer(ee_private_key).public_key_serializer.as_der()
        public_key_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(public_key_bytes)
        public_key_file_name = f'public_key_{public_key_sha256_fingerprint}.der'

        dev_id_module = DevIdModule(tmp_path)
        dev_id_module.initialize()

        dev_id_module.insert_ldevid_key(PrivateKeySerializer(ee_private_key))

        with open(tmp_path / Path('key_inventory.json'), 'r') as f:
            key_inventory = KeyInventory.model_validate_json(f.read())

        assert key_inventory.next_available_index == 1
        assert len(key_inventory.keys) == 1

        key_inventory_entry = key_inventory.keys[0]
        assert key_inventory_entry.key_index == 0
        assert key_inventory_entry.enabled is True
        assert key_inventory_entry.subject_public_key_info == key_type.value
        assert key_inventory_entry.used_by_idevid_certificate is False
        assert key_inventory_entry.private_key_file_name == private_key_file_name
        assert key_inventory_entry.private_key_sha256_fingerprint == private_key_sha256_fingerprint
        assert key_inventory_entry.public_key_file_name == public_key_file_name
        assert key_inventory_entry.public_key_sha256_fingerprint == public_key_sha256_fingerprint

    def test_insert_ldevid_certificate(self, tmp_path: Path) -> None:
        pass

    def insert_ldevid_certificate_chain(self, tmp_path: Path) -> None:
        pass