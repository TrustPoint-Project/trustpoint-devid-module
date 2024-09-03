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


class DevIdModuleNotImplementedError(DevIdModuleError):
    """If a method is not yet implemented."""

    def __init__(self, method_name: str) -> None:
        """Initializes the DevIdModuleNotImplementedError.

        Args:
            method_name: The name of the method that is not yet implemented.
        """
        super().__init__(f'Method {method_name} is not yet implemented.')


class CorruptedKeyDataError(DevIdModuleError):
    """Raised if the key data could not be loaded."""

    def __init__(self) -> None:
        """Initializes the CorruptedKeyDataError."""
        super().__init__('Failed to load the provided DevID Key. Either it is malformed or the password is incorrect.')


class CorruptedCertificateDataError(DevIdModuleError):
    """Raised if the certificate data could not be loaded."""

    def __init__(self) -> None:
        """Initializes the CorruptedCertificateDataError."""
        super().__init__('Failed to load the provided DevID Certificate. Data seems to be malformed.')


class CorruptedCertificateChainDataError(DevIdModuleError):
    """Raised if the certificate chain data could not be loaded."""

    def __init__(self) -> None:
        """Initializes the CorruptedCertificateChainDataError."""
        super().__init__('Failed to load the provided DevID Certificate Chain. Data seems to be malformed.')


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


class WorkingDirectoryAlreadyExistsError(DevIdModuleError):
    """Raised if the working directory exists while the operation does expect it to not exist."""

    def __init__(self) -> None:
        """Initializes the WorkingDirectoryAlreadyExistsError."""
        super().__init__('Working directory already exists.')


class InventoryDataWriteError(DevIdModuleError):
    """Raised if writing to the inventory data failed."""

    def __init__(self) -> None:
        """Initializes the InventoryDataWriteError."""
        super().__init__('Writing new data to the inventory failed.')


class PurgeError(DevIdModuleError):
    """Raised if purging the working directory failed."""

    def __init__(self) -> None:
        """Initializes the PurgeError."""
        super().__init__('Failed to purge the working directory.')


class DevIdModuleCorruptedError(DevIdModuleError):
    """Raised if the DevID Module stored data is corrupted."""
    def __init__(self) -> None:
        """Initializes the DevIdModuleCorruptedError."""
        super().__init__(
            'Critical Failure. DevID module data is corrupted.' 'You may need to call purge and thus remove all data.')


class NothingToPurgeError(DevIdModuleError):
    """Raised if the working directory to purge does not exist."""

    def __init__(self) -> None:
        """Initializes the NothingToPurgeError."""
        super().__init__('The working directory does not exist. Nothing to purge.')


class DevIdKeyNotFoundError(DevIdModuleError):
    """Raised if the required DevID Key was not found."""

    def __init__(self, key_index: None | int = None, public_key_sha256_fingerprint: None | str = None) -> None:
        """Initializes the DevIdKeyNotFoundError.

        Usually, either expects the key index or the sha256 fingerprint of the public key.

        Args:
            key_index: Index of the DevID Key that was not found.
            public_key_sha256_fingerprint: SHA256 Fingerprint of the public key that was not found.
        """
        if key_index is None and public_key_sha256_fingerprint is None:
            super().__init__('DevID Key not found.')
        elif key_index:
            super().__init__(f'DevID Key with key index {key_index} not found.')
        else:
            super().__init__(
                f'No matching DevID Key found for the SHA256 public key fingerprint: {public_key_sha256_fingerprint}.')


class DevIdKeyExistsError(DevIdModuleError):
    """Raised if the DevID Key already exists."""

    def __init__(self, key_index: int) -> None:
        """Initializes the DevIdKeyExistsError.

        Args:
            key_index: Key index of the DevID Key that already exists.
        """
        super().__init__(f'DevID Key already exists with key index {key_index}.')


class DevIdCertificateNotFoundError(DevIdModuleError):
    """Raised if the required DevID Certificate was not found."""

    def __init__(self, certificate_index: None | int = None, certificate_sha256_fingerprint: None | str = None) -> None:
        """Initializes the DevIdCertificateNotFoundError.

        Usually, either expects the certificate index or the sha256 fingerprint of the certificate.

        Args:
            certificate_index: Index of the DevID Certificate that was not found.
            certificate_sha256_fingerprint: SHA256 Fingerprint of the certificate that was not found.
        """
        if certificate_index is None and certificate_sha256_fingerprint is None:
            super().__init__('DevID Certificate not found.')
        elif certificate_index:
            super().__init__(f'DevID Certificate with certificate index {certificate_index} not found.')
        else:
            super().__init__(
                f'No matching DevID Certificate found for the SHA256 '
                f'certificate fingerprint: {certificate_sha256_fingerprint}.')


class DevIdCertificateExistsError(DevIdModuleError):
    """Raised if the DevID Certificate already exists."""

    def __init__(self, certificate_index: int) -> None:
        """Initializes the DevIdCertificateExistsError.

        Args:
            certificate_index: The certificate index of the DevID Certificate that already exists.
        """
        super().__init__(f'DevID Certificate already exists with certificate index {certificate_index}.')


class DevIdCertificateChainNotFoundError(DevIdModuleError):
    """Raised if the required DevID Certificate Chain was not found."""

    def __init__(self, certificate_index: int) -> None:
        """Initializes the DevIdCertificateChainNotFoundError.

        Args:
            certificate_index:
                The certificate index of the DevID Certificate that does not have an associated certificate chain.
        """
        super().__init__(
            f'No DevID Certificate Chain found for the DevID Certificate with certificate index {certificate_index}.')


class DevIdCertificateChainExistsError(DevIdModuleError):
    """Raised if the DevID Certificate Chain already exists."""

    def __init__(self, certificate_index: int) -> None:
        """Initializes the DevIdCertificateChainExistsError.

        Args:
            certificate_index:
                The certificate index of the DevID Certificate that already has an associated certificate chain.
        """
        super().__init__(
            f'The DevID Certificate Chain already exists for the DevID Certificate '
            f'with certificate index {certificate_index}.'
        )

class DevIdKeyIsDisabledError(DevIdModuleError):
    """Raised if the DevID Key is disabled, but the operation requires an enabled DevID Key."""

    def __init__(self, key_index: int) -> None:
        """Initializes the DevIdKeyIsDisabledError.

        Args:
            key_index: The key index of the DevID Key that is disabled.
        """
        super().__init__(f'The DevID Key with key index {key_index} is disabled.')


class DevIdCertificateIsDisabledError(DevIdModuleError):
    """Raised if the DevID Certificate is disabled, but the operation requires an enabled DevID Certificate."""

    def __init__(self, certificate_index: int) -> None:
        """Initializes the DevIdCertificateIsDisabledError.

        Args:
            certificate_index: The certificate index of the DevID Certificate that is disabled.
        """
        super().__init__(f'The DevID Certificate with certificate index {certificate_index} is disabled.')


class IDevIdKeyDeletionError(DevIdModuleError):
    """Raised if trying to delete an IDevID Key."""

    def __init__(self, key_index: int) -> None:
        """Initializes the IDevIdKeyDeletionError.

        Args:
            key_index: The key index of the IDevID Key that was tried to be deleted.
        """
        super().__init__(f'The DevID Key with key index {key_index} is an IDevID Key and thus cannot be deleted.')


class IDevIdCertificateDeletionError(DevIdModuleError):
    """Raised if trying to delete an IDevID Certificate."""

    def __init__(self, certificate_index: int) -> None:
        """Initializes the IDevIdCertificateDeletionError.

        Args:
            certificate_index: The certificate index of the IDevID Certificate that was tried to be deleted.
        """
        super().__init__(
            f'The DevID Certificate with certificate index {certificate_index} '
            'is an IDevID Certificate and thus cannot be deleted.')


class IDevIdCertificateChainDeletionError(DevIdModuleError):
    """Raised if trying to delete an IDevID Certificate Chain."""

    def __init__(self, certificate_index: int) -> None:
        """Initializes the IDevIdCertificateChainDeletionError.

        Args:
            certificate_index:
                The certificate index of the IDevID Certificate
                corresponding to the certificate chain that was tried to be deleted.
        """
        super().__init__(
            f'The DevID Certificate with certificate index {certificate_index} '
            'is an IDevID Certificate and thus its certificate chain cannot be deleted.')


class DevIdModule:
    """The Trustpoint DevID Module class."""
    _working_dir: Path

    _inventory_path: Path
    _inventory: None | Inventory = None

    def __init__(self, working_dir: str | Path) -> None:
        """Instantiates a DevIdModule object with the desired working directory.

        Args:
            working_dir: The desired working directory.

        Raises:
            DevIdModuleCorruptedError: If the DevID Module failed to load and verify the data from storage.
        """
        self._working_dir = Path(working_dir)
        self._inventory_path = self.working_dir / 'inventory.json'

        if self.inventory_path.exists() and self.inventory_path.is_file():
            try:
                with self.inventory_path.open('r') as f:
                    self._inventory = Inventory.model_validate_json(f.read())
                self._is_initialized = True
            except pydantic.ValidationError as exception:
                raise DevIdModuleCorruptedError from exception

    def initialize(self) -> None:
        """Initializes the DevID Module.

        Creates the working directory and the json inventory file.

        Raises:
            AlreadyInitializedError: If the DevID Module is already initialized.
            WorkingDirectoryAlreadyExists: If the working directory already exists.
            InventoryDataWriteError: If the DevID Module failed to write the inventory data to disc.
        """
        if self._inventory is not None:
            raise AlreadyInitializedError

        try:
            Path.mkdir(self.working_dir, parents=True, exist_ok=False)
        except FileExistsError as exception:
            raise WorkingDirectoryAlreadyExistsError from exception

        inventory = Inventory(
            next_key_index=0,
            next_certificate_index=0,
            devid_keys={},
            devid_certificates={},
            public_key_fingerprint_mapping={},
            certificate_fingerprint_mapping={},
        )

        try:
            self.inventory_path.write_text(inventory.model_dump_json())
        except Exception as exception:
            raise InventoryDataWriteError from exception
        self._inventory = inventory

    def purge(self) -> None:
        """Purges (deletes) all stored data corresponding to the DevID Module.

        Raises:
            NothingToPurgeError: If the working directory does not exist and thus there is nothing to purge.
            PurgeError: If the DevID Module failed to purge and delete the working directory.
        """
        try:
            shutil.rmtree(self.working_dir)
        except FileNotFoundError as exception:
            raise NothingToPurgeError from exception
        except Exception as exception:
            raise PurgeError from exception
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

        Raises:
            NotInitializedError: If the DevID Module is not yet initialized.
        """
        if self._inventory is None:
            raise NotInitializedError
        return self._inventory.model_copy()

    def _store_inventory(self, inventory: Inventory) -> None:
        try:
            self.inventory_path.write_text(inventory.model_dump_json())
            self._inventory = inventory
        except Exception as exception:
            raise InventoryDataWriteError from exception

    def insert_ldevid_key(
            self, private_key: bytes | str | PrivateKey | PrivateKeySerializer, password: None | bytes = None) -> int:
        """Inserts the LDevID private key corresponding to the provided key index.

        Args:
            private_key: The private key to be inserted.
            password: The password as bytes, if any. None, otherwise.

        Returns:
            int: The key index of the newly inserted private key.

        Raises:
            CorruptedKeyDataError: If the DevID Module failed to load the provided key data.
            NotInitializedError: If the DevID Module is not yet initialized.
            DevIdKeyExistsError: If the provided key is already stored as DevID Key.
            InventoryDataWriteError: If the DevID Module failed to write the inventory data to disc.
        """
        try:
            private_key = PrivateKeySerializer(private_key, password)
        except Exception as exception:
            raise CorruptedKeyDataError from exception

        signature_suite = SignatureSuite.get_signature_suite_from_private_key_type(private_key)

        private_key_bytes = private_key.as_pkcs8_pem()

        public_key_bytes = private_key.public_key_serializer.as_pem()
        public_key_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(public_key_bytes)

        inventory = self.inventory
        if public_key_sha256_fingerprint in inventory.public_key_fingerprint_mapping:
            raise DevIdKeyExistsError(
                key_index=inventory.public_key_fingerprint_mapping[public_key_sha256_fingerprint])

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

        Raises:
            CorruptedCertificateDataError: If the DevID Module failed to load the provided certificate data.
            NotInitializedError: If the DevID Module is not yet initialized.
            DevIdCertificateExistsError: If the DevID Certificate already exists.
            DevIdKeyNotFoundError: If no DevID Key was found that matches the provided certificate.
            InventoryDataWriteError: If the DevID Module failed to write the inventory data to disc.
        """
        try:
            certificate = CertificateSerializer(certificate)
        except Exception as exception:
            raise CorruptedCertificateDataError from exception
        public_key = certificate.public_key_serializer

        signature_suite = SignatureSuite.get_signature_suite_from_certificate(certificate)

        certificate_bytes = certificate.as_pem()
        certificate_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(certificate_bytes)

        inventory = self.inventory
        if certificate_sha256_fingerprint in inventory.certificate_fingerprint_mapping:
            raise DevIdCertificateExistsError(
                certificate_index=inventory.certificate_fingerprint_mapping[certificate_sha256_fingerprint])

        public_key_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(public_key.as_pem())

        key_index = inventory.public_key_fingerprint_mapping.get(public_key_sha256_fingerprint)

        if key_index is None:
            raise DevIdKeyNotFoundError

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

        Raises:
            CorruptedCertificateChainDataError: If the DevID Module failed to load the provided certificate chain data.
            NotInitializedError: If the DevID Module is not yet initialized.
            DevIdCertificateNotFoundError: If no DevID Certificate for the provided certificate index was found.
            DevIdCertificateChainExistsError: If the associated DevID Certificate already contains a certificate chain.
            InventoryDataWriteError: If the DevID Module failed to write the inventory data to disc.
        """
        try:
            certificate_chain = CertificateCollectionSerializer(certificate_chain)
        except Exception as exception:
            raise CorruptedCertificateChainDataError from exception

        inventory = self.inventory
        certificate = inventory.devid_certificates.get(certificate_index)

        if certificate is None:
            raise DevIdCertificateNotFoundError(certificate_index=certificate_index)

        if certificate.certificate_chain:
            raise DevIdCertificateChainExistsError(certificate_index=certificate_index)

        certificate.certificate_chain.extend(certificate_chain.as_pem_list())

        self._store_inventory(inventory)

        return certificate_index

    def delete_ldevid_key(self, key_index: int) -> None:
        """Deletes the LDevID key corresponding to the provided key index.

        This will also delete all corresponding LDevID certificates and LDevID certificate chains.

        Args:
            key_index: The key index for the key to be deleted.

        Raises:
            NotInitializedError: If the DevID Module is not yet initialized.
            DevIdKeyNotFoundError: If no DevID Key for the provided key index was found.
            IDevIdKeyDeletionError: If the DevID Key is an IDevID Key and thus cannot be deleted.
            InventoryDataWriteError: If the DevID Module failed to write the inventory data to disc.
        """
        inventory = self.inventory

        devid_key = inventory.devid_keys.get(key_index)

        if devid_key is None:
            raise DevIdKeyNotFoundError(key_index=key_index)

        if devid_key.is_idevid_key:
            raise IDevIdKeyDeletionError(key_index=key_index)

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

        Raises:
            NotInitializedError: If the DevID Module is not yet initialized.
            DevIdCertificateNotFoundError: If no DevID Certificate was found for the provided certificate index.
            IDevIdCertificateDeletionError:
                If the DevID Certificate is an IDevID certificate and thus cannot be deleted.
            InventoryDataWriteError: If the DevID Module failed to write the inventory data to disc.
        """
        inventory = self.inventory

        devid_certificate = inventory.devid_certificates.get(certificate_index)

        if devid_certificate is None:
            raise DevIdCertificateNotFoundError(certificate_index=certificate_index)

        if devid_certificate.is_idevid:
            raise IDevIdCertificateDeletionError(certificate_index=certificate_index)

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

        Raises:
            NotInitializedError: If the DevID Module is not yet initialized.
            DevIdCertificateNotFoundError: If the DevID Certificate was found for the provided certificate index.
            IDevIdCertificateChainDeletionError:
                If the DevID Certificate is an IDevID Certificate and thus its certificate chain cannot be deleted.
            DevIdCertificateChainNotFoundError: If the DevID Certificate has no associated certificate chain.
            InventoryDataWriteError: If the DevID Module failed to write the inventory data to disc.
        """
        inventory = self.inventory

        devid_certificate = inventory.devid_certificates.get(certificate_index)

        if devid_certificate is None:
            raise DevIdCertificateNotFoundError(certificate_index=certificate_index)

        if devid_certificate.is_idevid:
            IDevIdCertificateChainDeletionError(certificate_index=certificate_index)

        if not devid_certificate.certificate_chain:
            raise DevIdCertificateChainNotFoundError(certificate_index=certificate_index)

        devid_certificate.certificate_chain = []

        self._store_inventory(inventory)

    def add_rng_entropy(self, entropy: bytes) -> None:  # noqa: ARG002
        """Adds entropy to the RNG.

        Warnings:
            This is not yet implemented and will raise an DevIdModuleNotImplementedError.

        Args:
            entropy: Up to 256 random bytes.

        Raises:
            DevIdModuleNotImplementedError: Will be raised, since this method is not yet implemented.
        """
        raise DevIdModuleNotImplementedError(method_name='add_rng_entropy')

    def sign(self, key_index: int, data: bytes) -> bytes:
        """Signs the provided data (bytes) with the key corresponding to the provided key index.

        Args:
            key_index: Key index corresponding to the key that signs the data.
            data: The data to be signed.

        Returns:
            The signature of the provided data, signed by the key corresponding to the provided key index.
        """
        # TODO(AlexHx8472): Implement this method

    def enable_devid_key(self, key_index: int) -> None:
        """Enables the DevID key corresponding to the provided key index.

        Args:
            key_index: The key index of the key to be enabled.

        Raises:
            NotInitializedError: If the DevID Module is not yet initialized.
            DevIdKeyNotFoundError: If no DevID Key for the provided key index was found.
            InventoryDataWriteError: If the DevID Module failed to write the inventory data to disc.
        """
        inventory = self.inventory
        devid_key = inventory.devid_keys.get(key_index)

        if devid_key is None:
            raise DevIdKeyNotFoundError(key_index=key_index)

        inventory.devid_keys[key_index].is_enabled = True

        self._store_inventory(inventory)

    def disable_devid_key(self, key_index: int) -> None:
        """Disables the DevID key corresponding to the provided key index.

        Args:
            key_index: The key index of the key to be disabled.

        Raises:
            NotInitializedError: If the DevID Module is not yet initialized.
            DevIdKeyNotFoundError: If no DevID Key for the provided key index was found.
            InventoryDataWriteError: If the DevID Module failed to write the inventory data to disc.
        """
        inventory = self.inventory
        devid_key = inventory.devid_keys.get(key_index)

        if devid_key is None:
            raise DevIdKeyNotFoundError(key_index=key_index)

        inventory.devid_keys[key_index].is_enabled = False

        self._store_inventory(inventory)

    def enable_devid_certificate(self, certificate_index: int) -> None:
        """Enables the DevID certificate corresponding to the provided certificate index.

        Args:
            certificate_index: The certificate index of the certificate to be enabled.

        Raises:
            NotInitializedError: If the DevID Module is not yet initialized.
            DevIdCertificateNotFoundError: If the DevID Certificate was found for the provided certificate index.
            InventoryDataWriteError: If the DevID Module failed to write the inventory data to disc.
        """
        inventory = self.inventory
        devid_certificate = inventory.devid_certificates.get(certificate_index)

        if devid_certificate is None:
            raise DevIdCertificateNotFoundError(certificate_index=certificate_index)

        inventory.devid_keys[certificate_index].is_enabled = True

        self._store_inventory(inventory)

    def disable_devid_certificate(self, certificate_index: int) -> None:
        """Disables the DevID certificate corresponding to the provided certificate index.

        Args:
            certificate_index: The certificate index of the certificate to be disabled.

        Raises:
            NotInitializedError: If the DevID Module is not yet initialized.
            DevIdCertificateNotFoundError: If the DevID Certificate was found for the provided certificate index.
            InventoryDataWriteError: If the DevID Module failed to write the inventory data to disc.
        """
        inventory = self.inventory
        devid_certificate = inventory.devid_certificates.get(certificate_index)

        if devid_certificate is None:
            raise DevIdCertificateNotFoundError(certificate_index=certificate_index)

        inventory.devid_keys[certificate_index].is_enabled = False

        self._store_inventory(inventory)

    # TODO(AlexHx8472): Subject Public Key Info
    def enumerate_devid_public_keys(self) -> list[tuple[int, bool, str, bool]]:
        """Enumerates all DevID public keys.

        Returns:
            A list of 4-tuples containing the following:
            - int: key index (int)
            - bool: if the DevID Key is enabled (bool)
            - str: the subject public key info corresponding to the key and signature suite (str)
            - bool: if the DevID Key is an IDevID Key

        Raises:
            NotInitializedError: If the DevID Module is not yet initialized.
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
            - int: certificate index
            - int: corresponding key index
            - bool: if the DevID Certificate is enabled
            - bool: if the DevID Certificate is an IDevID Certificate
            - bytes: the certificate as DER encoded bytes

        Note:
            The first certificate in the list is the issuing ca certificate.
            The last certificate may be the root ca certificate, if it is included.

        Raises:
            NotInitializedError: If the DevID Module is not yet initialized.
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

        Note:
            The first certificate in the list is the issuing ca certificate.
            The last certificate may be the root ca certificate, if it is included.

        Raises:
            NotInitializedError: If the DevID Module is not yet initialized.
            DevIdCertificateNotFoundError: If the DevID Certificate was found for the provided certificate index.
            DevIdCertificateChainNotFoundError: If the DevID Certificate has no associated certificate chain.
            DevIdCertificateIsDisabledError:
                If the DevID Certificate associated with the certificate chain is disabled.
        """
        devid_certificate = self.inventory.devid_certificates.get(certificate_index)

        if devid_certificate is None:
            raise DevIdCertificateNotFoundError(certificate_index=certificate_index)

        if not devid_certificate.certificate_chain:
            raise DevIdCertificateChainNotFoundError(certificate_index=certificate_index)

        if devid_certificate.is_enabled is False:
            raise DevIdCertificateIsDisabledError(certificate_index=certificate_index)

        return [
            CertificateSerializer(certificate_bytes).as_der()
            for certificate_bytes in devid_certificate.certificate_chain
        ]
