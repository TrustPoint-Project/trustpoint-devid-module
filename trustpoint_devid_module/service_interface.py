"""The Trustpoint DevID Module Service Interface API."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import TYPE_CHECKING

import pydantic
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from trustpoint_devid_module.decorator import handle_unexpected_errors
from trustpoint_devid_module.exceptions import (
    AlreadyInitializedError,
    CorruptedCertificateChainDataError,
    CorruptedCertificateDataError,
    CorruptedKeyDataError,
    DataTypeError,
    DevIdCertificateChainExistsError,
    DevIdCertificateChainNotFoundError,
    DevIdCertificateExistsError,
    DevIdCertificateIsDisabledError,
    DevIdCertificateNotFoundError,
    DevIdKeyExistsError,
    DevIdKeyIsDisabledError,
    DevIdKeyNotFoundError,
    DevIdModuleCorruptedError,
    DevIdModuleNotImplementedError,
    EmptyDataError,
    IDevIdCertificateChainDeletionError,
    IDevIdCertificateDeletionError,
    IDevIdKeyDeletionError,
    InventoryDataWriteError,
    NothingToPurgeError,
    NotInitializedError,
    PurgeError,
    SignatureSuiteOfCertificateDoesNotMatchTheKeyError,
    UnexpectedDevIdModuleError,
    UnsupportedKeyTypeError,
    WorkingDirectoryAlreadyExistsError,
)
from trustpoint_devid_module.schema import DevIdCertificate, DevIdKey, Inventory
from trustpoint_devid_module.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    PrivateKeySerializer,
    PublicKeySerializer,
)
from trustpoint_devid_module.util import (
    PrivateKey,
    SignatureSuite,
    get_sha256_fingerprint_as_upper_hex_str,
)

if TYPE_CHECKING:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding
    from cryptography.hazmat.primitives.hashes import HashAlgorithm


# ---------------------------------------------------- DevID Module ----------------------------------------------------


class DevIdModule:
    """The Trustpoint DevID Module class."""
    _working_dir: Path

    _inventory_path: Path
    _inventory: None | Inventory = None

    @handle_unexpected_errors(message='Failed to instantiate the DevID Module.')
    def __init__(self, working_dir: str | Path, purge: bool = False) -> None:   # noqa: FBT001, FBT002
        """Instantiates a DevIdModule object with the desired working directory.

        Args:
            working_dir: The desired working directory.
            purge:
                If purge is True, the purge method is called without trying to load the inventory first.
                This prevents the DevIdModuleCorruptedError to be raised when trying to purge the working directory.

        Raises:
            DevIdModuleCorruptedError: If the DevID Module failed to load and verify the data from storage.
        """
        self._working_dir = Path(working_dir)
        self._inventory_path = self.working_dir / 'inventory.json'

        if purge:
            self.purge()
            return

        if self.inventory_path.exists() and self.inventory_path.is_file():
            try:
                with self.inventory_path.open('r') as f:
                    self._inventory = Inventory.model_validate_json(f.read())
                self._is_initialized = True
            except pydantic.ValidationError as exception:
                raise DevIdModuleCorruptedError from exception

    # --------------------------------------------- DevIdModule Properties ---------------------------------------------

    @property
    @handle_unexpected_errors(message='Failed to get the working directory.')
    def working_dir(self) -> Path:
        """Returns the Path instance containing the working directory path.

        Returns:
            Path: The Path instance containing the working directory path.
        """
        return self._working_dir

    @property
    @handle_unexpected_errors(message='Failed to get the inventory path.')
    def inventory_path(self) -> Path:
        """Returns the Path instance containing the inventory file path.

        Returns:
            Path: The Path instance containing the inventory file path.
        """
        return self._inventory_path

    @property
    @handle_unexpected_errors(message='Failed to get the inventory as a model copy.')
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

    # -------------------------------------- Initialization, Purging and Storing ---------------------------------------

    @handle_unexpected_errors(message='Failed to initialize the DevID Module.')
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

    @handle_unexpected_errors(message='Failed to purge the working directory.')
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

    @handle_unexpected_errors(message='Failed to store the inventory.')
    def _store_inventory(self, inventory: Inventory) -> None:
        try:
            self.inventory_path.write_text(inventory.model_dump_json())
            self._inventory = inventory
        except Exception as exception:
            raise InventoryDataWriteError from exception

    # ---------------------------------------------------- Entropy -----------------------------------------------------

    @handle_unexpected_errors(message='Failed to add entropy to the RNG.')
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

    # --------------------------------------------------- Insertions ---------------------------------------------------

    @handle_unexpected_errors(message='Failed to insert the LDevID Key.')
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
            UnsupportedKeyTypeError: If the provided key type is not supported by the DevID Module.
            NotInitializedError: If the DevID Module is not yet initialized.
            DevIdKeyExistsError: If the provided key is already stored as DevID Key.
            InventoryDataWriteError: If the DevID Module failed to write the inventory data to disc.
        """
        try:
            private_key = PrivateKeySerializer(private_key, password)
        except Exception as exception:
            raise CorruptedKeyDataError from exception

        try:
            _ = SignatureSuite.get_signature_suite_from_private_key_type(private_key)
        except Exception as exception:
            raise UnsupportedKeyTypeError from exception

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
            private_key=private_key_bytes,
            public_key=public_key_bytes,
        )

        # update the key inventory and public key fingerprint mapping
        inventory.next_key_index = new_key_index + 1
        inventory.public_key_fingerprint_mapping[public_key_sha256_fingerprint] = new_key_index
        inventory.devid_keys[new_key_index] = devid_key

        self._store_inventory(inventory)

        return new_key_index

    @handle_unexpected_errors(message='Failed to insert the LDevID Certificate.')
    def insert_ldevid_certificate(self, certificate: bytes | str | x509.Certificate | CertificateSerializer) -> int:
        """Inserts the LDevID certificate corresponding to the provided certificate index.

        Args:
            certificate: The certificate to be inserted.

        Returns:
            int: The certificate index of the newly inserted certificate.

        Raises:
            CorruptedCertificateDataError: If the DevID Module failed to load the provided certificate data.
            SignatureSuiteNotSupported: If the signature suite is not supported.
            SignatureSuiteOfCertificateDoesNotMatchTheKey:
            UnsupportedKeyTypeError: If the provided key type is not supported by the DevID Module.
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

        certificate_signature_suite = SignatureSuite.get_signature_suite_from_certificate(certificate)
        public_key_signature_suite = SignatureSuite.get_signature_suite_from_public_key_type(public_key)

        if certificate_signature_suite.signature_algorithm_oid != public_key_signature_suite.signature_algorithm_oid:
            raise SignatureSuiteOfCertificateDoesNotMatchTheKeyError

        if certificate_signature_suite.padding != public_key_signature_suite.padding:
            raise SignatureSuiteOfCertificateDoesNotMatchTheKeyError

        if certificate_signature_suite.public_key_algorithm_oid != public_key_signature_suite.public_key_algorithm_oid:
            raise SignatureSuiteOfCertificateDoesNotMatchTheKeyError

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
            certificate=certificate.as_pem(),
            certificate_chain=[],
        )

        inventory.next_certificate_index = new_certificate_index + 1
        inventory.devid_certificates[new_certificate_index] = devid_certificate
        inventory.devid_keys[key_index].certificate_indices.append(new_certificate_index)
        inventory.certificate_fingerprint_mapping[certificate_sha256_fingerprint] = new_certificate_index

        self._store_inventory(inventory)

        return new_certificate_index

    @handle_unexpected_errors(message='Failed to insert the LDevID Certificate Chain.')
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
            DevIdCertificateIsDisabledError:
                If the DevID Certificate associated with the certificate chain is disabled.
            DevIdCertificateChainExistsError: If the associated DevID Certificate already contains a certificate chain.
            InventoryDataWriteError: If the DevID Module failed to write the inventory data to disc.
        """
        try:
            certificate_chain = CertificateCollectionSerializer(certificate_chain)
        except Exception as exception:
            raise CorruptedCertificateChainDataError from exception

        inventory = self.inventory
        devid_certificate = inventory.devid_certificates.get(certificate_index)

        if devid_certificate is None:
            raise DevIdCertificateNotFoundError(certificate_index=certificate_index)

        if devid_certificate.is_enabled is False:
            raise DevIdCertificateIsDisabledError(certificate_index=certificate_index)

        if devid_certificate.certificate_chain:
            raise DevIdCertificateChainExistsError(certificate_index=certificate_index)

        devid_certificate.certificate_chain.extend(certificate_chain.as_pem_list())

        self._store_inventory(inventory)

        return certificate_index

    # --------------------------------------------------- Deletions ----------------------------------------------------

    @handle_unexpected_errors(message='Failed to delete the LDevID Key.')
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

    @handle_unexpected_errors(message='Failed to delete the LDevID Certificate.')
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

    @handle_unexpected_errors(message='Failed to delete the LDevID Certificate Chain.')
    def delete_ldevid_certificate_chain(self, certificate_index: int) -> None:
        """Deletes the LDevID certificate chain corresponding to the certificate with the provided certificate index.

        Args:
            certificate_index: The certificate index for the certificate containing the certificate chain to be deleted.

        Raises:
            NotInitializedError: If the DevID Module is not yet initialized.
            DevIdCertificateNotFoundError: If the DevID Certificate was found for the provided certificate index.
            IDevIdCertificateChainDeletionError:
                If the DevID Certificate is an IDevID Certificate and thus its certificate chain cannot be deleted.
            DevIdCertificateIsDisabledError:
                If the DevID Certificate associated with the certificate chain is disabled.
            DevIdCertificateChainNotFoundError: If the DevID Certificate has no associated certificate chain.
            InventoryDataWriteError: If the DevID Module failed to write the inventory data to disc.
        """
        inventory = self.inventory
        devid_certificate = inventory.devid_certificates.get(certificate_index)

        if devid_certificate is None:
            raise DevIdCertificateNotFoundError(certificate_index=certificate_index)

        if devid_certificate.is_idevid:
            IDevIdCertificateChainDeletionError(certificate_index=certificate_index)

        if devid_certificate.is_enabled is False:
            raise DevIdCertificateIsDisabledError(certificate_index=certificate_index)

        if not devid_certificate.certificate_chain:
            raise DevIdCertificateChainNotFoundError(certificate_index=certificate_index)

        devid_certificate.certificate_chain = []

        self._store_inventory(inventory)

    # ---------------------------------- Enable / Disable DevID Keys and Certificates ----------------------------------

    @handle_unexpected_errors(message='Failed to enable the DevID Key.')
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

    @handle_unexpected_errors(message='Failed to disable the DevID Key.')
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

    @handle_unexpected_errors(message='Failed to enable the DevID Certificate.')
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

        inventory.devid_certificates[certificate_index].is_enabled = True

        self._store_inventory(inventory)

    @handle_unexpected_errors(message='Failed to disable the DevID Certificate.')
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

        inventory.devid_certificates[certificate_index].is_enabled = False

        self._store_inventory(inventory)

    # -------------------------------------------------- Enumerations --------------------------------------------------

    @handle_unexpected_errors(message='Failed to enumerate the DevID Public Keys.')
    def enumerate_devid_public_keys(self) -> list[tuple[int, bool, bytes, bool]]:
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
                PublicKeySerializer(devid_key.public_key).as_der(),
                devid_key.is_idevid_key,
            )
            for devid_key_index, devid_key in self.inventory.devid_keys.items()
        ]

    @handle_unexpected_errors(message='Failed to enumerate the DevID Certificates.')
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

    @handle_unexpected_errors(message='Failed to enumerate the corresponding DevID Certificate Chain.')
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

    # ---------------------------------------------------- Signing -----------------------------------------------------

    @handle_unexpected_errors(message='Failed to sign the provided data with the requested DevID Key.')
    def sign(self, key_index: int, data: bytes) -> bytes:
        """Signs the provided data (bytes) with the key corresponding to the provided key index.

        Args:
            key_index: Key index corresponding to the key that signs the data.
            data: The data to be signed.

        Returns:
            The signature of the provided data, signed by the key corresponding to the provided key index.

        Raises:
            DataTypeError: If the provided data is not a bytes object.
            EmptyDataError: If the provided data is an empty bytes object.
            NotInitializedError: If the DevID Module is not yet initialized.
            DevIdKeyNotFoundError: If no DevID Key for the provided key index was found.
            DevIdKeyIsDisabledError: If the DevID Key for the provided key index is disabled.
            UnexpectedDevIdModuleError: If the DevID Key for the provided key index has an unsupported key type.
        """
        if not isinstance(data, bytes):
            raise DataTypeError(data=data)

        if not data:
            raise EmptyDataError

        inventory = self.inventory
        devid_key = inventory.devid_keys.get(key_index)

        if devid_key is None:
            raise DevIdKeyNotFoundError(key_index=key_index)

        if devid_key.is_enabled is False:
            raise DevIdKeyIsDisabledError(key_index=key_index)

        try:
            private_key = PrivateKeySerializer(devid_key.private_key)
            signature_suite = SignatureSuite.get_signature_suite_from_private_key_type(private_key)
        except Exception as exception:
            raise UnexpectedDevIdModuleError(
                message=f'The key type of the DevID Key with key index {key_index} is not supported.') from exception

        crypto_private_key = private_key.as_crypto()
        if isinstance(signature_suite.private_key_type, rsa.RSAPrivateKey):
            return self._sign_data_with_rsa_key(
                crypto_private_key,
                data,
                signature_suite.padding,
                signature_suite.hash_algorithm())

        if isinstance(signature_suite.private_key_type, ec.EllipticCurvePrivateKey):
            return self._sign_data_with_ec_key_and_ecdsa(crypto_private_key, data, signature_suite.hash_algorithm())

        raise UnexpectedDevIdModuleError(
            message=(
                f'The key type of the DevID Key with key index {key_index} '
                f'found in the inventory is not supported for signing operations.'))

    @staticmethod
    def _sign_data_with_rsa_key(
            private_key: PrivateKey,
            data: bytes,
            padding: AsymmetricPadding,
            hash_algorithm: HashAlgorithm) -> bytes:
        return private_key.sign(
            data,
            padding,
            hash_algorithm)

    @staticmethod
    def _sign_data_with_ec_key_and_ecdsa(private_key: PrivateKey, data: bytes, hash_algorithm: HashAlgorithm) -> bytes:
        return private_key.sign(data, ec.ECDSA(hash_algorithm))
