"""This module contains basic X.509 validations as required by the DevID Module."""
import abc

from cryptography import x509
import datetime

from trustpoint_devid_module.serializer import CertificateSerializer, CertificateCollectionSerializer
from trustpoint_devid_module.util import SignatureSuite


# TODO(AlexHx8472): Validation of both DevID Certificates and DevID Certificate Chains.

class DevIdValidator(abc.ABC):

    _warnings: list[str]
    _certificate_serializer: CertificateSerializer
    _signature_suite: SignatureSuite

    @property
    def certificate_serializer(self) -> CertificateSerializer:
        return self._certificate_serializer

    @property
    def certificate(self) -> x509.Certificate:
        return self.certificate_serializer.as_crypto()

    @property
    def signature_suite(self) -> SignatureSuite:
        return self._signature_suite

    @abc.abstractmethod
    def validate(self) -> None:
        pass

    @staticmethod
    def _get_basic_constraints_extension_values(certificate: x509.Certificate) -> None | tuple[bool, None | int]:
        try:
            basic_constraints_extension = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:
            return None
        return basic_constraints_extension.value.ca, basic_constraints_extension.value.path_length

    def _check_validity(self, certificate: x509.Certificate) -> None:
        # Expired or not yet valid certificates are not excluded,
        # since the system time could be incorrect at the time of insertion.
        if certificate.not_valid_before > datetime.datetime.now(datetime.timezone.utc):
            self._warnings.append(
                f'The Certificate with subject {certificate.subject.rfc4514_string()} '
                f'is not yet valid. Valid not before: {certificate.not_valid_before}.')
        if certificate.not_valid_after < datetime.datetime.now(datetime.timezone.utc):
            self._warnings.append(
                f'The Certificate with subject {certificate.subject.rfc4514_string()} '
                f'is expired. Valid not after: {certificate.not_valid_after}.')


class DevIdCertificateValidator(DevIdValidator):

    _certificate_serializer: CertificateSerializer

    def __init__(self, certificate: x509.Certificate, signature_suite: SignatureSuite) -> None:
        self._certificate = certificate
        self._signature_suite = signature_suite

    def validate(self) -> bool:
        basic_constraints_extension = self._get_basic_constraints_extension_values(self.certificate)
        if basic_constraints_extension is not None:
            ca, path_length_constraint = basic_constraints_extension
            if ca:
                raise ValueError

        if self.signature_suite != SignatureSuite.get_signature_suite_from_certificate(self.certificate_serializer):
            raise ValueError

        self._check_validity(self.certificate)

        return True


class DevIdCertificateChainValidator(DevIdValidator):

    _certificate_serializer: CertificateSerializer

    def __init__(self, certificate_serializer: CertificateSerializer, certificate_chain: CertificateCollectionSerializer, signature_suite: SignatureSuite) -> None:
        self._certificate_serializer = certificate_serializer
        self._certificate_chain = certificate_chain

    def validate(self) -> bool:
        certificate_chain = self._certificate_chain.as_crypto_list()

        checked_certificates = []

        min_path_length = 0
        current_certificate = self.certificate
        while True:
            for certificate in certificate_chain:
                if current_certificate.verify_directly_issued_by(certificate):
                    self._validate_certificate_in_chain(certificate, min_path_length)
                    checked_certificates.append(certificate)
                    current_certificate = certificate
            else:
                break

        return True

    def _validate_certificate_in_chain(self, certificate: x509.Certificate, min_path_length: int) -> None:
        basic_constraints_extension = self._get_basic_constraints_extension_values(certificate)
        if basic_constraints_extension is not None:
            ca, path_length_constraint = basic_constraints_extension
            if not ca:
                raise ValueError
            if min_path_length is not None and path_length_constraint < min_path_length:
                raise ValueError

        certificate_serializer = CertificateSerializer(certificate)
        if self.signature_suite != SignatureSuite.get_signature_suite_from_certificate(certificate_serializer):
            raise ValueError

        self._check_validity(certificate)
