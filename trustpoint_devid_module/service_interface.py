"""The Trustpoint DevID Module Service Interface API."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import TYPE_CHECKING

import pydantic

from trustpoint_devid_module.schema import DevIdCertificate, DevIdKey, Inventory
from trustpoint_devid_module.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    PrivateKeySerializer,
)
from trustpoint_devid_module.util import (
    PrivateKey,
    SignatureSuite,
    get_sha256_fingerprint_as_upper_hex_str,
)

if TYPE_CHECKING:
    from cryptography import x509


class DevIdModuleError(Exception):
    """Base class for all DevID Module Exceptions."""
    def __init__(self, message: str) -> None:
        """Initializes the DevIdModuleError."""
        super().__init__(message)


class NotInitializedError(DevIdModuleError):
    """Raised if trying to use the DevID Module"""

    def __init__(self) -> None:
        """Initializes the NotInitializedError."""
        super().__init__('DevID Module is not initialized.')


class AlreadyInitializedError(DevIdModuleError):
    """Raised if trying to initialize the DevID Module when it is already initialized."""

    def __init__(self) -> None:
        """Initializes the AlreadyInitializedError."""
        super().__init__('Already initialized.')


class DevIdModuleCorruptedError(DevIdModuleError):
    """Raised if the DevID Module stored data is corrupted."""
    def __init__(self) -> None:
        """Initializes the DevIdModuleCorruptedError."""
        super().__init__(
            'Critical Failure. DevID module data is corrupted.' 'You may need to call purge and thus remove all data.'
        )


class NothingToPurgeError(DevIdModuleError):
    """Raised if the working directory to purge does not exist."""

    def __init__(self) -> None:
        """Initializes the NothingToPurgeError."""
        super().__init__('The working directory does not exist. Nothing to purge.')


class DevIdModule:
    """The Trustpoint DevID Module class."""
    _working_dir: Path

    _inventory_path: Path
    _inventory: None | Inventory = None

    def __init__(self, working_dir: str | Path) -> None:
        """Instantiates a DevIdModule object with the desired working directory.

        Args:
            working_dir: The desired working directory.
        """
        self._working_dir = Path(working_dir)
        self._inventory_path = self.working_dir / 'inventory.json'

        if self.inventory_path.exists() and self.inventory_path.is_file():
            try:
                with self.inventory_path.open('r') as f:
                    self._inventory = Inventory.model_validate_json(f.read())
                self._is_initialized = True
            except pydantic.ValidationError as exception:
                err_msg = 'Failed to load inventory. Data seems to be corrupt.'
                raise RuntimeError(err_msg) from exception

    def initialize(self) -> None:
        """Initializes the DevID Module.

        Creates the working directory and the json inventory file.
        """
        # TODO(AlexHx8472): Exception handling
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
            certificate_fingerprint_mapping={},
        )

        self.inventory_path.write_text(inventory.model_dump_json())
        self._inventory = inventory

    def purge(self) -> None:
        """Purges (deletes) all stored data corresponding to the DevID Module."""
        shutil.rmtree(self.working_dir, ignore_errors=True)
        self._inventory = None

    @property
    def working_dir(self) -> Path:
        """Returns the Path instance containing the working directory path.

        Returns:
            Path: The Path instance containing the working directory path.
        """
        return self._working_dir

    @property
    def inventory_path(self) -> Path:
        """Returns the Path instance containing the inventory file path.

        Returns:
            Path: The Path instance containing the inventory file path.
        """
        return self._inventory_path

    @property
    def inventory(self) -> Inventory:
        """Returns the current inventory as a model copy.

        Returns:
            Inventory: A model copy of the current inventory.
        """
        return self._inventory.model_copy()

    def _store_inventory(self, inventory: Inventory) -> None:
        self.inventory_path.write_text(inventory.model_dump_json())
        self._inventory = inventory

    def insert_ldevid_key(
            self, private_key: bytes | str | PrivateKey | PrivateKeySerializer, password: None | bytes = None) -> int:
        """Inserts the LDevID private key corresponding to the provided key index.

        Args:
            private_key: The private key to be inserted.
            password: The password as bytes, if any. None, otherwise.

        Returns:
            int: The key index of the newly inserted private key.
        """
        inventory = self.inventory.model_copy()

        # get private key serializer
        private_key = PrivateKeySerializer(private_key, password)

        # get key type and signature suite
        signature_suite = SignatureSuite.get_signature_suite_from_private_key_type(private_key)

        private_key_bytes = private_key.as_pkcs8_pem()

        public_key_bytes = private_key.public_key_serializer.as_pem()
        public_key_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(public_key_bytes)

        # TODO(AlexHx8472): Exception handling
        if public_key_sha256_fingerprint in inventory.public_key_fingerprint_mapping:
            err_msg = 'Key already stored.'
            raise ValueError(err_msg)

        new_key_index = inventory.next_key_index
        devid_key = DevIdKey(
            key_index=new_key_index,
            certificate_indices=[],
            is_enabled=False,
            is_idevid_key=False,
            subject_public_key_info=signature_suite.value.encode(),
            private_key=private_key_bytes,
            public_key=public_key_bytes,
        )

        # update the key inventory and public key fingerprint mapping
        inventory.next_key_index = new_key_index + 1
        inventory.public_key_fingerprint_mapping[public_key_sha256_fingerprint] = new_key_index
        inventory.devid_keys[new_key_index] = devid_key

        self._store_inventory(inventory)

        return new_key_index

    def insert_ldevid_certificate(self, certificate: bytes | str | x509.Certificate | CertificateSerializer) -> int:
        """Inserts the LDevID certificate corresponding to the provided certificate index.

        Args:
            certificate: The certificate to be inserted.

        Returns:
            int: The certificate index of the newly inserted certificate.
        """
        inventory = self.inventory.model_copy()
        certificate = CertificateSerializer(certificate)
        public_key = certificate.public_key_serializer

        # get key type and signature suite
        signature_suite = SignatureSuite.get_signature_suite_from_certificate(certificate)

        certificate_bytes = certificate.as_pem()
        certificate_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(certificate_bytes)

        public_key_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(public_key.as_pem())

        key_index = inventory.public_key_fingerprint_mapping.get(public_key_sha256_fingerprint)

        # TODO(AlexHx8472): Exception handling
        if key_index is None:
            err_msg = 'No matching key for the provided certificate found.'
            raise ValueError(err_msg)

        new_certificate_index = inventory.next_certificate_index
        devid_certificate = DevIdCertificate(
            certificate_index=new_certificate_index,
            key_index=key_index,
            is_enabled=False,
            is_idevid=False,
            subject_public_key_info=signature_suite.value.encode(),
            certificate=certificate.as_pem(),
            certificate_chain=[],
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
        certificate_chain: \
            bytes | str \
            | list[bytes | str | x509.Certificate | CertificateSerializer] \
            | CertificateCollectionSerializer
    ) -> int:
        """Inserts the LDevID certificate chain corresponding to the certificate with the provided certificate index.

        Args:
            certificate_index:
                The certificate index for the certificate corresponding to the certificate chain to be inserted.
            certificate_chain: The certificate chain to be inserted.

        Returns:
            int: The certificate index of the certificate containing the newly inserted certificate chain.
        """
        certificate_chain = CertificateCollectionSerializer(certificate_chain)
        inventory = self.inventory.model_copy()

        certificate = inventory.devid_certificates.get(certificate_index)

        # TODO(AlexHx8472): Exception handling
        if certificate is None:
            err_msg = 'No certificate for certificate index found.'
            raise ValueError(err_msg)

        certificate.certificate_chain.extend(certificate_chain.as_pem_list())

        self._store_inventory(inventory)

        return certificate_index

    def delete_ldevid_key(self, key_index: int) -> None:
        """Deletes the LDevID key corresponding to the provided key index.

        This will also delete all corresponding LDevID certificates and LDevID certificate chains.

        Args:
            key_index: The key index for the key to be deleted.
        """
        inventory = self.inventory.model_copy()

        devid_key = inventory.devid_keys.get(key_index)

        # TODO(AlexHx8472): Exception handling
        if devid_key is None:
            err_msg = 'No key for key index found.'
            raise ValueError(err_msg)

        # TODO(AlexHx8472): Exception handling
        if devid_key.is_idevid_key:
            err_msg = 'This key is an IDevID key. Cannot delete it.'
            raise ValueError(err_msg)

        for certificate_index in devid_key.certificate_indices:
            del inventory.devid_certificates[certificate_index]
            inventory.certificate_fingerprint_mapping = {
                fingerprint: index
                for fingerprint, index in inventory.certificate_fingerprint_mapping.items()
                if index != certificate_index
            }

        del inventory.devid_keys[key_index]

        inventory.public_key_fingerprint_mapping = {
            fingerprint: index
            for fingerprint, index in inventory.public_key_fingerprint_mapping.items()
            if index != key_index
        }

        self._store_inventory(inventory)

    def delete_ldevid_certificate(self, certificate_index: int) -> None:
        """Deletes the LDevID certificate corresponding to the provided certificate index.

        This will also delete the contained LDevID certificate chain, if any.

        Args:
            certificate_index: The certificate index for the certificate to be deleted.
        """
        inventory = self.inventory.model_copy()

        devid_certificate = inventory.devid_certificates.get(certificate_index)

        # TODO(AlexHx8472): Exception handling
        if devid_certificate is None:
            err_msg = 'No certificate for the certificate index found.'
            raise ValueError(err_msg)

        # TODO(AlexHx8472): Exception handling
        if devid_certificate.is_idevid:
            err_msg = 'This certificate is an IDevID certificate. Cannot delete it.'
            raise ValueError(err_msg)

        del inventory.devid_certificates[certificate_index]
        inventory.certificate_fingerprint_mapping = {
            fingerprint: index
            for fingerprint, index in inventory.certificate_fingerprint_mapping.items()
            if index != certificate_index
        }

        self._store_inventory(inventory)

    def delete_ldevid_certificate_chain(self, certificate_index: int) -> None:
        """Deletes the LDevID certificate chain corresponding to the certificate with the provided certificate index.

        Args:
            certificate_index: The certificate index for the certificate containing the certificate chain to be deleted.
        """
        inventory = self.inventory.model_copy()

        devid_certificate = inventory.devid_certificates.get(certificate_index)

        # TODO(AlexHx8472): Exception handling
        if devid_certificate is None:
            err_msg = 'No certificate for the certificate index found.'
            raise ValueError(err_msg)

        # TODO(AlexHx8472): Exception handling
        if devid_certificate.is_idevid:
            err_msg = 'This certificate chain is part of an IDevID certificate. Cannot delete it.'
            raise ValueError(err_msg)

        # TODO(AlexHx8472): Exception handling
        if not devid_certificate.certificate_chain:
            err_msg = 'No certificate chain found to delete for the provided certificate index.'
            raise ValueError(err_msg)

        devid_certificate.certificate_chain = []

        self._store_inventory(inventory)

    def add_rng_entropy(self, entropy: bytes) -> None:  # noqa: ARG002
        """Adds entropy to the RNG.

        Args:
            entropy: Up to 256 random bytes.
        """
        # TODO(AlexHx8472): Exception handling
        err_msg = 'Not yet implemented.'
        raise NotImplementedError(err_msg)

    def sign(self, key_index: int, data: bytes) -> bytes:
        """Signs the provided data (bytes) with the key corresponding to the provided key index.

        Args:
            key_index: Key index corresponding to the key that signs the data.
            data: The data to be signed.

        Returns:
            The signature of the provided data, signed by the key corresponding to the provided key index.
        """

    def enable_devid_key(self, key_index: int) -> None:
        """Enables the DevID key corresponding to the provided key index.

        Args:
            key_index: The key index of the key to be enabled.
        """
        inventory = self.inventory.model_copy()
        devid_key = inventory.devid_keys.get(key_index)

        # TODO(AlexHx8472): Exception handling
        if devid_key is None:
            err_msg = 'No key for key index found.'
            raise ValueError(err_msg)

        inventory.devid_keys[key_index].is_enabled = True

        self._store_inventory(inventory)

    def disable_devid_key(self, key_index: int) -> None:
        """Disables the DevID key corresponding to the provided key index.

        Args:
            key_index: The key index of the key to be disabled.
        """
        inventory = self.inventory.model_copy()
        devid_key = inventory.devid_keys.get(key_index)

        # TODO(AlexHx8472): Exception handling
        if devid_key is None:
            err_msg = 'No key for key index found.'
            raise ValueError(err_msg)

        inventory.devid_keys[key_index].is_enabled = False

        self._store_inventory(inventory)

    def enable_devid_certificate(self, certificate_index: int) -> None:
        """Enables the DevID certificate corresponding to the provided certificate index.

        Args:
            certificate_index: The certificate index of the certificate to be enabled.
        """
        inventory = self.inventory.model_copy()
        devid_certificate = inventory.devid_certificates.get(certificate_index)

        # TODO(AlexHx8472): Exception handling
        if devid_certificate is None:
            err_msg = 'No certificate for certificate index found.'
            raise ValueError(err_msg)

        inventory.devid_keys[certificate_index].is_enabled = True

        self._store_inventory(inventory)

    def disable_devid_certificate(self, certificate_index: int) -> None:
        """Disables the DevID certificate corresponding to the provided certificate index.

        Args:
            certificate_index: The certificate index of the certificate to be disabled.
        """
        inventory = self.inventory.model_copy()
        devid_certificate = inventory.devid_certificates.get(certificate_index)

        # TODO(AlexHx8472): Exception handling
        if devid_certificate is None:
            err_msg = 'No certificate for certificate index found.'
            raise ValueError(err_msg)

        inventory.devid_keys[certificate_index].is_enabled = False

        self._store_inventory(inventory)

    # TODO(AlexHx8472): Subject Public Key Info
    def enumerate_devid_public_keys(self) -> list[tuple[int, bool, str, bool]]:
        """Enumerates all DevID public keys.

        Returns:
            A list of 4-tuples containing the following:
            - key_index (int)
            - is_enabled (bool)
            - subject_public_key_info (str)
            - is_devid_key (bool)
        """
        return [
            (
                devid_key_index,
                devid_key.is_enabled,
                devid_key.subject_public_key_info.decode(),
                devid_key.is_idevid_key,
            )
            for devid_key_index, devid_key in self.inventory.devid_keys.items()
        ]

    def enumerate_devid_certificates(self) -> list[tuple[int, int, bool, bool, bytes]]:
        """Enumerates all DevID certificates.

        Returns:
            A list of 5-tuples containing the following:
            - certificate index
            - corresponding key index
            -
            The first certificate in the list is the issuing ca certificate.
            The last certificate may be the root ca certificate, if it is included.
        """
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
        """Enumerates the DevID certificate chain corresponding to the certificate with the given certificate index.

        Args:
            certificate_index:
                The certificate index of the certificate of which the certificate chain shall be returned.

        Returns:
            A list of certificates in DER encoded bytes.
            The first certificate in the list is the issuing ca certificate.
            The last certificate may be the root ca certificate, if it is included.
        """
        devid_certificate = self.inventory.devid_certificates.get(certificate_index)

        # TODO(AlexHx8472): Exception handling
        if devid_certificate is None:
            err_msg = 'No certificate for certificate index found.'
            raise ValueError(err_msg)

        # TODO(AlexHx8472): Exception handling
        if not devid_certificate.certificate_chain:
            err_msg = 'No certificate chain found for the provided certificate index.'
            raise ValueError(err_msg)

        # TODO(AlexHx8472): Exception handling
        if devid_certificate.is_enabled is False:
            err_msg = 'The DevID certificate with given certificate_index is disabled.'
            raise ValueError(err_msg)

        return [
            CertificateSerializer(certificate_bytes).as_der()
            for certificate_bytes in devid_certificate.certificate_chain
        ]
