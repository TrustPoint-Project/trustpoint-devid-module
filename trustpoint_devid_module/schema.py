from __future__ import annotations


from pydantic import BaseModel, ConfigDict

from trustpoint_devid_module.util import KeyType, SignatureSuite


# -------------------------------------------------------- Keys --------------------------------------------------------


class KeyInventoryEntry(BaseModel):
    """Key inventory entry containing all corresponding information."""

    model_config = ConfigDict(strict=True, extra="forbid")

    key_index: int
    enabled: bool
    subject_public_key_info: str
    signature_suite: SignatureSuite
    key_type: KeyType
    used_by_idevid_certificate: bool
    private_key: str
    public_key: str
    private_key_sha256_fingerprint: str
    public_key_sha256_fingerprint: str


class KeyInventory(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    next_available_index: int
    keys: list[KeyInventoryEntry]


class EnumeratedPublicKey(BaseModel):
    model_config = ConfigDict(strict=True, extra="allow")

    key_index: int
    enabled: bool
    subject_public_key_info: str
    used_by_idevid_certificate: bool


class EnumeratedPublicKeys(BaseModel):
    model_config = ConfigDict(strict=True, extra="allow")

    public_keys: list[EnumeratedPublicKey]


# ---------------------------------------------------- Certificates ----------------------------------------------------


class CertificateInventoryEntry(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    certificate_index: int
    key_index: None | int
    enabled: bool
    is_idevid_certificate: bool
    certificate_file_name: str
    certificate_sha256_fingerprint: str
    certificate_chain_file_name: None | str
    certificate_chain_sha256_fingerprint: None | str


class CertificateInventory(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    next_available_index: int
    certificates: list[CertificateInventoryEntry]


class EnumeratedCertificate(BaseModel):
    model_config = ConfigDict(strict=True, extra="allow")

    certificate_index: int
    key_index: None | int
    enabled: bool
    is_idevid_certificate: bool
    certificate: str


class EnumeratedCertificates(BaseModel):
    model_config = ConfigDict(strict=True, extra="allow")

    certificates: list[EnumeratedCertificate]
