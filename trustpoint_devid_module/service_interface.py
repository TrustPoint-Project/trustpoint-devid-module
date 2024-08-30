from __future__ import annotations

import shutil
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed448, ed25519

from trustpoint_devid_module.serializer import PrivateKeySerializer

from trustpoint_devid_module.util import (
    get_sha256_fingerprint_as_upper_hex_str,
    KeyType,
    PrivateKey,
    SignatureSuite,
)
from trustpoint_devid_module.schema import (
    KeyInventory,
    KeyInventoryEntry,
    EnumeratedPublicKeys,
)
from trustpoint_devid_module.schema import (
    CertificateInventory,
    CertificateInventoryEntry,
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

    _private_key_inventory_path: Path
    _certificate_inventory_path: Path

    _is_initialized: bool = False

    def __init__(self, working_dir: str | Path) -> None:
        self._working_dir = Path(working_dir)
        self._key_inventory_path = self.working_dir / "key_inventory.json"
        self._certificate_inventory_path = (
            self.working_dir / "certificate_inventory.json"
        )
        self._certificate_chain_inventory_path = (
            self.working_dir / "certificate_chain_inventory.json"
        )

        if not self._working_dir.exists():
            self._is_initialized = True

    def initialize(self) -> None:
        Path.mkdir(self.working_dir, parents=True)

        with open(self.key_inventory_path, "w") as f:
            f.write(KeyInventory(next_available_index=0, keys=[]).model_dump_json())

        with open(self.certificate_inventory_path, "w") as f:
            f.write(
                CertificateInventory(
                    next_available_index=0, certificates=[]
                ).model_dump_json()
            )

    def purge(self) -> None:
        shutil.rmtree(self.working_dir, ignore_errors=True)

    def verify_data(self) -> None:
        self._check_data_consistency_deep()

    def _check_data_consistency_shallow(self) -> None:
        if not self._working_dir.exists():
            raise NotInitializedError
        if not self._working_dir.is_dir():
            raise DevIdModuleCorrupted
        if (
            not self.key_inventory_path.exists()
            or not self.key_inventory_path.is_file()
        ):
            raise DevIdModuleCorrupted
        if (
            not self.certificate_inventory_path.exists()
            or not self.certificate_inventory_path.is_file()
        ):
            raise DevIdModuleCorrupted

    def _check_data_consistency_deep(self) -> None:
        pass

    @property
    def working_dir(self) -> Path:
        return self._working_dir

    @property
    def key_inventory_path(self) -> Path:
        return self._key_inventory_path

    @property
    def certificate_inventory_path(self) -> Path:
        return self._certificate_inventory_path

    def _get_key_inventory(self) -> KeyInventory:
        with open(self._key_inventory_path, "r") as f:
            key_inventory_data = f.read()

        return KeyInventory.model_validate_json(key_inventory_data)

    def _get_certificate_inventory(self) -> CertificateInventory:
        with open(self._certificate_inventory_path, "r") as f:
            certificate_inventory_data = f.read()

        return CertificateInventory.model_validate_json(certificate_inventory_data)

    def enumerate_devid_public_keys(self) -> None | EnumeratedPublicKeys:
        pass

    def enumerate_devid_certificates(self) -> None:
        pass

    def enumerate_devid_certificate_chain(self, certificate_index: int) -> None:
        pass

    def sign(self, key_index: int) -> None:
        pass

    def enable_devid_certificate(self, certificate_index: int) -> None:
        pass

    def disable_devid_certificate(self, certificate_index: int) -> None:
        pass

    def enable_devid_key(self, key_index: int) -> None:
        pass

    def disable_devid_key(self, key_index: int) -> None:
        pass

    def generate_ldevid_key(self, key_type: str) -> int:
        if key_type == KeyType.RSA2048:
            return self._generate_rsa_ldevid_key(key_size=2048)
        if key_type == KeyType.RSA3072:
            return self._generate_rsa_ldevid_key(key_size=3072)
        if key_type == KeyType.RSA4096:
            return self._generate_rsa_ldevid_key(key_size=4096)
        if key_type == KeyType.SECP256R1:
            return self._generate_secp_r1_ldevid_key(key_size=256)
        if key_type == KeyType.SECP384R1:
            return self._generate_secp_r1_ldevid_key(key_size=384)
        if key_type == KeyType.ED448:
            return self._generate_ed448_ldevid_key()
        if key_type == KeyType.ED25519:
            return self._generate_ed25519_ldevid_key()

    def _generate_rsa_ldevid_key(self, key_size: int) -> int:
        return self.insert_ldevid_key(
            PrivateKeySerializer(
                rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            )
        )

    def _generate_secp_r1_ldevid_key(self, key_size: int) -> int:
        if key_size == 256:
            curve = ec.SECP256R1()
        elif key_size == 384:
            curve = ec.SECP384R1()
        else:
            raise ValueError

        return self.insert_ldevid_key(
            PrivateKeySerializer(ec.generate_private_key(curve))
        )

    def _generate_ed448_ldevid_key(self) -> int:
        return self.insert_ldevid_key(
            PrivateKeySerializer(ed448.Ed448PrivateKey.generate())
        )

    def _generate_ed25519_ldevid_key(self) -> int:
        return self.insert_ldevid_key(
            PrivateKeySerializer(ed25519.Ed25519PrivateKey.generate())
        )

    def insert_ldevid_key(
        self,
        private_key: bytes | str | PrivateKey | PrivateKeySerializer,
        password: None | bytes = None,
    ) -> int:
        # get bytes in DER format, sha256 fingerprints and file names of both the private and public key
        private_key = PrivateKeySerializer(private_key, password)
        private_key_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(
            private_key.as_pkcs1_der()
        )
        public_key_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(
            private_key.public_key_serializer.as_der()
        )

        # get key type and signature suite
        key_type = KeyType.get_key_type_from_private_key(private_key.as_crypto())
        signature_suite = SignatureSuite.get_signature_suite_from_key_type(key_type)

        # check if private key already exists
        if (
            self._get_key_entry_by_public_key_sha256_fingerprint(
                public_key_sha256_fingerprint
            )
            is not None
        ):
            raise ValueError('Already in DB.')

        # construct the new key entry for the key inventory
        key_inventory = self._get_key_inventory()
        new_key_inventory_entry = KeyInventoryEntry(
            key_index=key_inventory.next_available_index,
            enabled=False,
            subject_public_key_info='Not Yet Implemented',
            signature_suite=signature_suite,
            key_type=key_type,
            used_by_idevid_certificate=False,
            private_key=private_key.as_pkcs1_pem().decode(),
            public_key=private_key.public_key_serializer.as_pem().decode(),
            private_key_sha256_fingerprint=private_key_sha256_fingerprint,
            public_key_sha256_fingerprint=public_key_sha256_fingerprint,
        )

        # update the key inventory
        key_inventory.next_available_index += 1
        key_inventory.keys.append(new_key_inventory_entry)
        self._store_key_inventory(key_inventory)

        # store private and public key in DER (PKCS#8) format
        return new_key_inventory_entry.key_index

    # def insert_ldevid_certificate(self, certificate: bytes | str | x509.Certificate | CertificateSerializer) -> int:
    #     # get fingerprints for both the certificate and public_key
    #     certificate = CertificateSerializer(certificate)
    #     certificate_sha256_fingerprint = certificate.as_crypto().fingerprint(hashes.SHA256()).hex().upper()
    #     public_key_sha256_fingerprint = get_sha256_fingerprint_as_upper_hex_str(
    #         certificate.public_key_serializer.as_der())
    #
    #     # check if certificate already exists
    #     if self._get_certificate_entry_by_certificate_sha256_fingerprint(certificate_sha256_fingerprint) is not None:
    #         raise ValueError('Already in DB.')
    #
    #     # check that there is exactly one key pair available that matches the public key contained in the certificate
    #     private_key_entry = self._get_key_entry_by_public_key_sha256_fingerprint(public_key_sha256_fingerprint)
    #     if private_key_entry is None:
    #         raise ValueError('Matching private key not found in DB.')
    #
    #     # construct the new entry for the certificate inventory
    #     certificate_inventory = self._get_certificate_inventory()
    #     new_certificate_entry = CertificateInventoryEntry(
    #         certificate_index=certificate_inventory.next_available_index,
    #         key_index=private_key_entry.key_index,
    #         enabled=True,
    #         is_idevid_certificate=False,
    #         certificate_sha256_fingerprint=get_sha256_fingerprint_as_upper_hex_str(certificate.as_der()),
    #         certificate_chain_file_name=None,
    #         certificate_chain_sha256_fingerprint=None
    #     )
    #
    #     # update the certificate inventory
    #     certificate_inventory.next_available_index += 1
    #     certificate_inventory.certificates.append(new_certificate_entry)
    #     self._store_certificate_inventory(certificate_inventory)
    #
    #     # store the certificate in DER format
    #     certificate_file_name = f'certificate_{certificate_sha256_fingerprint}.der'
    #     with open(certificate_file_name, 'wb') as f:
    #         f.write(certificate.as_der())
    #
    #
    #     return new_certificate_entry.key_index

    # def insert_ldevid_certificate_chain(
    #         self,
    #         certificate_chain: CertificateCollectionSerializer,
    #         certificate_index: int) -> None:
    #
    #     # getting the certificate_entry for the certificate index
    #     certificate_entry = self._get_certificate_entry_by_certificate_index(certificate_index=certificate_index)
    #     if certificate_entry is None:
    #         raise ValueError('No certificate found for given index.')
    #
    #     # check there is no chain installed already
    #     if certificate_entry.certificate_chain_file_name or certificate_entry.certificate_chain_sha256_fingerprint:
    #         raise ValueError('Certificate chain already installed for given certificate index.')
    #
    #     cert_path = certificate_entry.certificate_file_name
    #     with open(self.working_dir / cert_path, 'rb') as f:
    #         certificate_serializer = CertificateSerializer(f.read())
    #
    #     crypto_cert_chain = []
    #     current_cert = certificate_serializer.as_crypto()
    #
    #     while current_cert is not None:
    #     for certificate in certificate_chain.as_crypto_list():
    #         if current_cert.verify_directly_issued_by(certificate):
    #             crypto_cert_chain.append(certificate)
    #             if current_cert.sub
    #             break

    # def delete_ldevid_key(self, key_index: int) -> None:
    #     """Deletes the LDevID Key and all corresponding certificates and chains.
    #
    #     Args:
    #         key_index: The index of the key to delete.
    #
    #     Raises:
    #
    #     """
    #     key_inventory = self._get_key_inventory()
    #     certificate_inventory = self._get_certificate_inventory()
    #
    #     for key in key_inventory.keys:
    #         if key.key_index == key_index:
    #             key_to_delete = key
    #             break
    #     else:
    #         raise ValueError
    #
    #     key_inventory.keys.remove(key_to_delete)
    #     Path.unlink(self.working_dir / Path(key_to_delete.private_key_file_name))
    #     Path.unlink(self.working_dir / Path(key_to_delete.public_key_file_name))
    #     self._store_key_inventory(key_inventory)
    #
    #     certificates = [
    #         certificate_entry for certificate_entry in certificate_inventory.certificates
    #             if certificate_entry.key_index != key_to_delete.key_index]
    #
    #     for certificate in certificates:
    #         Path.unlink(self.working_dir / Path(certificate.certificate_file_name))
    #
    #     if len(certificates) != len(certificate_inventory.certificates):
    #         certificate_inventory.certificates = certificates
    #         self._store_certificate_inventory(certificate_inventory)

    # def delete_ldevid_certificate(self, certificate_index: int) -> None:
    #     """Deletes the certificate and the corresponding certificate chain, if any.
    #
    #     Args:
    #         certificate_index: The index of the certificate to delete.
    #
    #     Raises:
    #
    #     """
    #     certificate_to_delete = self._get_certificate_entry_by_certificate_index(certificate_index=certificate_index)
    #     if certificate_to_delete.certificate_chain_file_name:
    #         cert_chain_path = self.working_dir / certificate_to_delete.certificate_chain_file_name
    #         Path.unlink(cert_chain_path)
    #
    #     cert_path = self.working_dir / certificate_to_delete.certificate_file_name
    #     Path.unlink(cert_path)
    #
    #     certificate_inventory = self._get_certificate_inventory()
    #     certificate_inventory.certificates.remove(certificate_to_delete)
    #     self._store_certificate_inventory(certificate_inventory)

    def _store_key_inventory(self, key_inventory: KeyInventory) -> None:
        with open(self._key_inventory_path, "w") as f:
            f.write(key_inventory.model_dump_json())

    def _store_certificate_inventory(
        self, certificate_inventory: CertificateInventory
    ) -> None:
        with open(self._certificate_inventory_path, "w") as f:
            f.write(certificate_inventory.model_dump_json())

    def _get_key_entry_by_key_index(self, key_index: int) -> None | KeyInventoryEntry:
        keys_with_key_index = [
            key_entry
            for key_entry in self._get_key_inventory().keys
            if key_entry.key_index == key_index
        ]
        if len(keys_with_key_index) == 0:
            return None
        if len(keys_with_key_index) > 1:
            raise DevIdModuleCorrupted
        return keys_with_key_index[0]

    def _get_key_entry_by_public_key_sha256_fingerprint(
        self, public_key_sha256_fingerprint: str
    ) -> None | KeyInventoryEntry:
        keys_with_sha256_fingerprint = [
            key_entry
            for key_entry in self._get_key_inventory().keys
            if key_entry.public_key_sha256_fingerprint == public_key_sha256_fingerprint
        ]
        if len(keys_with_sha256_fingerprint) == 0:
            return None
        if len(keys_with_sha256_fingerprint) > 1:
            raise DevIdModuleCorrupted
        return keys_with_sha256_fingerprint[0]

    def _get_certificate_entry_by_certificate_index(
        self, certificate_index: int
    ) -> None | CertificateInventoryEntry:
        certificate_with_certificate_index = [
            certificate_entry
            for certificate_entry in self._get_certificate_inventory().certificates
            if certificate_entry.certificate_index == certificate_index
        ]
        if len(certificate_with_certificate_index) == 0:
            return None
        if len(certificate_with_certificate_index) > 1:
            raise DevIdModuleCorrupted
        return certificate_with_certificate_index[0]

    def _get_certificate_entry_by_certificate_sha256_fingerprint(
        self, certificate_sha256_fingerprint: str
    ) -> None | CertificateInventoryEntry:
        certificates_with_sha256_fingerprint = [
            certificate_entry
            for certificate_entry in self._get_certificate_inventory().certificates
            if certificate_entry.certificate_sha256_fingerprint
            == certificate_sha256_fingerprint
        ]
        if len(certificates_with_sha256_fingerprint) == 0:
            return None
        if len(certificates_with_sha256_fingerprint) > 1:
            raise DevIdModuleCorrupted
        return certificates_with_sha256_fingerprint[0]

    def _get_key_entry_by_certificate_index(
        self, certificate_index: int
    ) -> None | KeyInventoryEntry:
        certificate_entry = self._get_certificate_entry_by_certificate_index(
            certificate_index=certificate_index
        )
        return self._get_key_entry_by_key_index(certificate_entry.key_index)

    def _get_certificate_entries_by_key_index(
        self, key_index: int
    ) -> list[CertificateInventoryEntry]:
        return [
            certificate_entry
            for certificate_entry in self._get_certificate_inventory().certificates
            if certificate_entry.key_index == key_index
        ]
