from __future__ import annotations

import shutil
from pathlib import Path
import pydantic
from cryptography import x509


from trustpoint_devid_module.serializer import (
    PrivateKeySerializer,
    CertificateSerializer,
    CertificateCollectionSerializer)

from trustpoint_devid_module.util import (
    get_sha256_fingerprint_as_upper_hex_str,
    PrivateKey,
    SignatureSuite,
)
from trustpoint_devid_module.schema import (
    DevIdCertificate,
    DevIdKey,
    Inventory
)


class DevIdModuleError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class NotInitializedError(DevIdModuleError):
    def __init__(self) -> None:
        super().__init__("DevID Module is not initialized.")


class AlreadyInitializedError(DevIdModuleError):
    def __init__(self) -> None:
        super().__init__("Already initialized.")


class DevIdModuleCorrupted(DevIdModuleError):
    def __init__(self) -> None:
        super().__init__(
            "Critical Failure. DevID module data is corrupted."
            "You may need to call purge and thus remove all data."
        )


class NothingToPurge(DevIdModuleError):
    def __init__(self) -> None:
        super().__init__("The working directory does not exist. Nothing to purge.")


class DevIdModule:
    _working_dir: Path

    _inventory_path: Path
    _inventory: None | Inventory = None

    def __init__(self, working_dir: str | Path) -> None:
        self._working_dir = Path(working_dir)
        self._inventory_path = self.working_dir / 'inventory.json'

        if self.inventory_path.exists() and self.inventory_path.is_file():
            try:
                with open(self.inventory_path, 'r') as f:
                    self._inventory = Inventory.model_validate_json(f.read())
                self._is_initialized = True
            except pydantic.ValidationError:
                err_msg = 'Failed to load inventory. Data seems to be corrupt.'
                raise RuntimeError(err_msg)


    def initialize(self) -> None:
        if self._inventory is not None:
            err_msg = 'Trustpoint DevID Module is already initialized.'
            raise RuntimeError(err_msg)

        Path.mkdir(self.working_dir, parents=True)

        inventory = Inventory(
            next_key_index=0,
            next_certificate_index=0,

            devid_keys={},
            devid_certificates={},

            public_key_fingerprint_mapping={},
            certificate_fingerprint_mapping={})

        self.inventory_path.write_text(inventory.model_dump_json())
        self._inventory = inventory

    def purge(self) -> None:
        shutil.rmtree(self.working_dir, ignore_errors=True)
        self._inventory = None

    @property
    def working_dir(self) -> Path:
        return self._working_dir

    @property
    def inventory_path(self) -> Path:
        return self._inventory_path

    @property
    def inventory(self) -> Inventory:
        return self._inventory

    def _store_inventory(self, inventory: Inventory) -> None:
        self.inventory_path.write_text(inventory.model_dump_json())
        self._inventory = inventory

    def insert_ldevid_key(
            self,
            private_key: bytes | str | PrivateKey | PrivateKeySerializer,
            password: None | bytes = None) -> int:

        inventory = self.inventory.model_copy()

        # get private key serializer
        private_key = PrivateKeySerializer(private_key, password)

        # get key type and signature suite
        signature_suite = SignatureSuite.get_signature_suite_from_private_key_type(private_key)

        private_key_bytes = private_key.as_pkcs8_pem()

        public_key_bytes = private_key.public_key_serializer.as_pem()
        public_key_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(public_key_bytes)

        if public_key_sha256_fingerprint in inventory.public_key_fingerprint_mapping.keys():
            raise ValueError('Key already stored.')

        new_key_index = inventory.next_key_index
        devid_key = DevIdKey(
            key_index=new_key_index,
            certificate_indices=[],

            is_enabled=False,
            is_idevid_key=False,

            subject_public_key_info=signature_suite.value.encode(),

            private_key=private_key_bytes,
            public_key=public_key_bytes)

        # update the key inventory and public key fingerprint mapping
        inventory.next_key_index = new_key_index + 1
        inventory.public_key_fingerprint_mapping[public_key_sha256_fingerprint] = new_key_index
        inventory.devid_keys[new_key_index] = devid_key

        self._store_inventory(inventory)

        return new_key_index

    def insert_ldevid_certificate(self, certificate: bytes | str | x509.Certificate | CertificateSerializer) -> int:
        inventory = self.inventory.model_copy()
        certificate = CertificateSerializer(certificate)
        public_key = certificate.public_key_serializer

        # get key type and signature suite
        signature_suite = SignatureSuite.get_signature_suite_from_certificate(certificate)

        certificate_bytes = certificate.as_pem()
        certificate_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(certificate_bytes)

        public_key_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(public_key.as_pem())

        key_index = inventory.public_key_fingerprint_mapping.get(public_key_sha256_fingerprint)
        if key_index is None:
            raise ValueError('No matching key for the provided certificate found.')

        new_certificate_index = inventory.next_certificate_index
        devid_certificate = DevIdCertificate(
            certificate_index = new_certificate_index,
            key_index = key_index,

            is_enabled=False,
            is_idevid=False,

            subject_public_key_info=signature_suite.value.encode(),
            certificate=certificate.as_pem(),
            certificate_chain=[]
        )

        inventory.next_certificate_index = new_certificate_index + 1
        inventory.devid_certificates[new_certificate_index] = devid_certificate
        inventory.devid_keys[key_index].certificate_indices.append(new_certificate_index)
        inventory.certificate_fingerprint_mapping[certificate_sha256_fingerprint] = new_certificate_index

        self._store_inventory(inventory)

        return new_certificate_index

    def insert_ldevid_certificate_chain(
            self,
            certificate_index: int,
            certificate_collection: \
                    bytes | str \
                    | list[bytes | str | x509.Certificate | CertificateSerializer] \
                    | CertificateCollectionSerializer
    ) -> int:
        certificate_chain = CertificateCollectionSerializer(certificate_collection)
        inventory = self.inventory.model_copy()

        certificate = inventory.devid_certificates.get(certificate_index)
        if certificate is None:
            raise ValueError('No certificate for certificate index found.')

        certificate.certificate_chain.extend(certificate_chain.as_pem_list())

        self._store_inventory(inventory)

        return certificate_index


    def delete_ldevid_key(self, key_index: int) -> None:
        inventory = self.inventory.model_copy()

        devid_key = inventory.devid_keys.get(key_index)
        if devid_key is None:
            raise ValueError('No key for key index found.')

        if devid_key.is_idevid_key:
            raise ValueError('This key is an IDevID key. Cannot delete it.')

        for certificate_index in devid_key.certificate_indices:
            del inventory.devid_certificates[certificate_index]
            inventory.certificate_fingerprint_mapping = {
                fingerprint:index for fingerprint, index in inventory.certificate_fingerprint_mapping.items()
                if index != certificate_index
            }

        del inventory.devid_keys[key_index]

        inventory.public_key_fingerprint_mapping = {
            fingerprint:index for fingerprint, index in inventory.public_key_fingerprint_mapping.items()
            if index != key_index
        }

        self._store_inventory(inventory)


    def delete_ldevid_certificate(self, certificate_index: int) -> None:
        inventory = self.inventory.model_copy()

        devid_certificate = inventory.devid_certificates.get(certificate_index)
        if devid_certificate is None:
            raise ValueError('No certificate for the certificate index found.')

        if devid_certificate.is_idevid:
            raise ValueError('This certificate is an IDevID certificate. Cannot delete it.')

        del inventory.devid_certificates[certificate_index]
        inventory.certificate_fingerprint_mapping = {
            fingerprint: index for fingerprint, index in inventory.certificate_fingerprint_mapping.items()
            if index != certificate_index
        }

        self._store_inventory(inventory)


    def delete_ldevid_certificate_chain(self, certificate_index: int) -> None:
        inventory = self.inventory.model_copy()

        devid_certificate = inventory.devid_certificates.get(certificate_index)
        if devid_certificate is None:
            raise ValueError('No certificate for the certificate index found.')

        if devid_certificate.is_idevid:
            raise ValueError('This certificate chain is part of an IDevID certificate. Cannot delete it.')

        if not devid_certificate.certificate_chain:
            raise ValueError('No certificate chain found to delete for the provided certificate index.')

        devid_certificate.certificate_chain = []

        self._store_inventory(inventory)

    def add_rng_entropy(self, entropy: bytes) -> None:
        raise NotImplementedError('Not yet implemented.')

    def sign(self, key_index: int, data: bytes) -> bytes:
        pass

    def enable_devid_key(self, key_index: int) -> None:
        inventory = self.inventory.model_copy()
        devid_key = inventory.devid_keys.get(key_index)
        if devid_key is None:
            raise ValueError('No key for key index found.')

        inventory.devid_keys[key_index].is_enabled = True

        self._store_inventory(inventory)

    def disable_devid_key(self, key_index: int) -> None:
        inventory = self.inventory.model_copy()
        devid_key = inventory.devid_keys.get(key_index)
        if devid_key is None:
            raise ValueError('No key for key index found.')

        inventory.devid_keys[key_index].is_enabled = False

        self._store_inventory(inventory)

    def enable_devid_certificate(self, certificate_index: int) -> None:
        inventory = self.inventory.model_copy()
        devid_certificate = inventory.devid_certificates.get(certificate_index)
        if devid_certificate is None:
            raise ValueError('No certificate for certificate index found.')

        inventory.devid_keys[certificate_index].is_enabled = True

        self._store_inventory(inventory)

    def disable_devid_certificate(self, certificate_index: int) -> None:
        inventory = self.inventory.model_copy()
        devid_certificate = inventory.devid_certificates.get(certificate_index)
        if devid_certificate is None:
            raise ValueError('No certificate for certificate index found.')

        inventory.devid_keys[certificate_index].is_enabled = False

        self._store_inventory(inventory)

    # TODO: Subject Public Key Info
    def enumerate_devid_public_keys(self) -> list[tuple[int, bool, str, bool]]:
        enumerated_public_keys = []
        for devid_key_index, devid_key in self.inventory.devid_keys.items():
            enumerated_public_keys.append(
                (
                    devid_key_index,
                    devid_key.is_enabled,
                    devid_key.subject_public_key_info.decode(),
                    devid_key.is_idevid_key)
            )

        return enumerated_public_keys

    def enumerate_devid_certificates(self) -> list[tuple[int, int, bool, bool, bytes]]:
        enumerated_certificates = []
        for devid_certificate_index, devid_certificate in self.inventory.devid_certificates.items():
            enumerated_certificates.append(
                (
                    devid_certificate_index,
                    devid_certificate.key_index,
                    devid_certificate.is_enabled,
                    devid_certificate.is_idevid,
                    CertificateSerializer(devid_certificate.certificate).as_der(),
                )
            )

        return enumerated_certificates

    def enumerate_devid_certificate_chain(self, certificate_index: int) -> list[bytes]:
        devid_certificate = self.inventory.devid_certificates.get(certificate_index)
        if devid_certificate is None:
            raise ValueError('No certificate for certificate index found.')

        if not devid_certificate.certificate_chain:
            raise ValueError('No certificate chain found for the provided certificate index.')

        if devid_certificate.is_enabled is False:
            raise ValueError('The DevID certificate with given certificate_index is disabled.')

        certificate_chain = []
        for certificate_bytes in devid_certificate.certificate_chain:
            certificate_chain.append(CertificateSerializer(certificate_bytes).as_der())

        return certificate_chain
