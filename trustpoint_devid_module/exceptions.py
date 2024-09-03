"""Module containing all custom exceptions."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


# ------------------------------------------------- Custom Exceptions --------------------------------------------------


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


class UnsupportedKeyTypeError(DevIdModuleError):
    """Raised if the provided key type is not supported by the DevID Module."""

    def __init__(self) -> None:
        """Initializes the UnsupportedKeyTypeError."""
        super().__init__('The provided key type is not supported by the DevID Module.')


class UnexpectedDevIdModuleError(DevIdModuleError):
    """Raised if an unexpected error occurred, e.g. not supported key type found in the inventory."""

    def __init__(self, message: str, exception: None | Exception = None) -> None:
        """Initializes the UnexpectedDevIdModuleError.

        Args:
            message: Description of the error that occurred.
            exception: The exception that caused this exception.
        """
        if exception is None:
            super().__init__(f'\n\n\tAn unexpected error occurred.\n\t{message}\n')
        else:
            super().__init__(f'\n\n\tAn unexpected error occurred.\n\t{message}\n\tException raised: {exception}\n')

class DataTypeError(DevIdModuleError):
    """Raised if the provided data is not of type bytes."""

    def __init__(self, data: Any) -> None:
        """Initializes the DataTypeError.

        Args:
            data: The data object received.
        """
        super().__init__(f'Expected data to be of type bytes, but got {type(data)}.')


class EmptyDataError(DevIdModuleError):
    """Raised if the provided data is an empty bytes object."""

    def __init__(self) -> None:
        """Initializes the EmptyDataError."""
        super().__init__('The provided data object is an empty bytes object.')


class SignatureSuiteNotSupportedError(DevIdModuleError):
    """Raised if the provided certificate uses a signature suite that is not supported."""

    def __init__(self) -> None:
        """Initializes the SignatureSuiteNotSupported."""
        super().__init__('The provided certificate uses a signature suite that is not supported.')


class SignatureSuiteOfCertificateDoesNotMatchTheKeyError(DevIdModuleError):
    """Raised if the provided certificate uses a different signature suite than the stored DevID key."""

    def __init__(self) -> None:
        """Initializes the SignatureSuiteOfCertificateDoesNotMatchTheKey."""
        super().__init__('The provided certificate uses a different signature suite than the stored DevID key.')
