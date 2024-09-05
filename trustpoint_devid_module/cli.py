"""Click cli application for the Trustpoint DevID Module."""

from __future__ import annotations

from pathlib import Path

import click
from prettytable import PrettyTable

from trustpoint_devid_module.exceptions import NotInitializedError
from trustpoint_devid_module.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    PrivateKeySerializer, PublicKeySerializer,
)
from trustpoint_devid_module.service_interface import DevIdModule
from trustpoint_devid_module.util import WORKING_DIR


def get_devid_module(working_dir: Path = WORKING_DIR) -> DevIdModule:
    """Instantiates the DevIdModule class with the desired working directory.

    Args:
        working_dir: Path to the desired working directory.

    Returns:
        DevIdModule: An instance of the DevIdModule class.
    """
    return DevIdModule(working_dir=working_dir, purge=False)


def get_devid_module_for_purge(working_dir: Path = WORKING_DIR) -> DevIdModule:
    """Instantiates the DevIdModule class with the desired working directory and the purge flag set to True.

    Args:
        working_dir: Path to the desired working directory.

    Returns:
        DevIdModule: An instance of the DevIdModule class.
    """
    return DevIdModule(working_dir=working_dir, purge=True)


def get_initialized_devid_module(working_dir: Path = WORKING_DIR) -> None | DevIdModule:
    """Instantiates the DevIdModule class and tries to load the stored DevID Module data.

    Args:
        working_dir: Path to the desired working directory.

    Returns:
        None | DevIdModule:
            An instance of the DevIdModule class if the initialization
            with existing data was successful, None otherwise.
    """
    devid_module = DevIdModule(working_dir)
    if devid_module.inventory is None:
        click.echo('DevID Module is not yet initialized.')
        return None
    return devid_module


@click.group()
def cli() -> None:
    """Trustpoint DevID Module"""


@cli.command()
def status() -> None:
    """Status information about the DevID Module."""
    devid_module = get_devid_module()
    try:
        if devid_module.inventory:
            click.echo(f'\nDevID Module is initialized with working directory: {devid_module.working_dir}.\n')
            return
    except NotInitializedError:
        click.echo('\nDevID Module is not yet initialized.\n')


@cli.command()
def initialize() -> None:
    """Initializes the DevID Module."""
    devid_module = get_devid_module()

    devid_module.initialize()
    click.echo('\nDevID Module successfully initialized.\n')


@cli.command()
def purge() -> None:
    """Purges all stored data and secrets."""
    if click.confirm('\nAre you sure to purge the DevID Module? This will irreversibly delete all data and secrets!\n'):
        get_devid_module_for_purge()
        click.echo('\nDevID Module successfully purged.\n')


# ----------------------------------------------------- enumerate ------------------------------------------------------


@cli.group(name='enumerate')
def enumerate_() -> None:
    """Lists LDevID Keys, Certificates and Certificate Chains."""


@enumerate_.command(name='devid-public-keys')
def enumerate_devid_public_keys() -> None:
    """Lists all DevID public keys."""
    devid_module = get_devid_module()
    table = PrettyTable()
    table.field_names = ['Key Index', 'Is Enabled', 'Subject Public Key Info', 'Is IDevID']
    table.add_rows([
        (
            entry[0],
            entry[1],
            PublicKeySerializer(entry[2]).as_pem().decode(),
            entry[3]
        ) for entry in devid_module.enumerate_devid_public_keys()])
    click.echo(f'\n{table}\n')


def _format_certificate_enumeration(
    devid_certificates_enumeration: list[tuple[int, int, bool, bool, bytes]],
) -> list[tuple[int, int, bool, bool]]:
    return [
        (entry[0], entry[1], entry[2], entry[3])
        for entry in devid_certificates_enumeration
    ]


def _format_certificate_enumeration_with_certificates(
    devid_certificates_enumeration: list[tuple[int, int, bool, bool, bytes]],
) -> list[tuple[int, int, bool, bool, str]]:
    return [
        (entry[0], entry[1], entry[2], entry[3], CertificateSerializer(entry[4]).as_pem().decode())
        for entry in devid_certificates_enumeration
    ]


@enumerate_.command(name='devid-certificates')
@click.option('--show-certificates', '-s', required=False, default=False, is_flag=True)
def enumerate_devid_certificates(show_certificates: bool) -> None:  # noqa: FBT001
    """Lists all DevID public keys.

    Args:
        show_certificates: Also prints the certificates in PEM format if this flag is set (True).
    """
    devid_module = get_devid_module()
    table = PrettyTable()
    if show_certificates:
        table.field_names = ['Certificate Index', 'Key Index', 'Is Enabled', 'Is IDevID', 'Certificate']
        table.add_rows(_format_certificate_enumeration_with_certificates(devid_module.enumerate_devid_certificates()))
    else:
        table.field_names = ['Certificate Index', 'Key Index', 'Is Enabled', 'Is IDevID']
        table.add_rows(_format_certificate_enumeration(devid_module.enumerate_devid_certificates()))
    click.echo(f'\n{table}\n')


@enumerate_.command(name='devid-certificate-chains')
@click.option('--certificate-index', '-i', required=True, type=int, help='The corresponding certificate index.')
def enumerate_devid_certificate_chains(certificate_index: int) -> None:
    """Lists all DevID certificates contained in the chain.

    Args:
        certificate_index: The certificate index of the certificate that contains the desired certificate chain.
    """
    devid_module = get_devid_module()
    devid_certificate_ = devid_module.inventory.devid_certificates.get(certificate_index)
    if devid_certificate_ is None:
        click.echo(f'\nNo DevID certificate found with the given index {certificate_index}.\n')
        return
    if not devid_certificate_.certificate_chain:
        click.echo(
            f'\nDevID certificate with certificate index {certificate_index} '
            f'has no corresponding certificate chain stored.\n'
        )
        return

    table = PrettyTable()
    table.field_names = ['# Certificate', 'Certificate']

    devid_certificate_chain = [
        CertificateSerializer(certificate).as_pem().decode() for certificate in devid_certificate_.certificate_chain
    ]
    table.add_rows(list(enumerate(devid_certificate_chain)))
    click.echo(f'\n{table}\n')


# ------------------------------------------------------- insert -------------------------------------------------------


@cli.group()
def insert() -> None:
    """Insert LDevID Keys, Certificates and Certificate Chains."""


@insert.command(name='ldevid-key')
@click.option('--password', '-p', default=None, required=False, help='Password, if the key file is encrypted.')
@click.argument('file_path', required=True, type=click.Path(exists=True))
def insert_ldevid_key(password: str, file_path: Path) -> None:
    """Inserts an LDevID Private Key.

    Args:
        password: The password, if the key file is encrypted.
        file_path: File path to the key file.
    """
    file_path = Path(file_path)
    if password is not None:
        password = password.encode()
    devid_module = get_initialized_devid_module()
    if devid_module is None:
        return

    with file_path.open('rb') as f:
        key_bytes = f.read()

    # TODO(AlexHx8472): Exception handling
    try:
        key_serializer = PrivateKeySerializer(key_bytes, password)
        key_index = devid_module.insert_ldevid_key(key_serializer)
    except Exception as exception:  # noqa: BLE001
        click.echo(f'\n{exception}\n')
        return

    click.echo(f'\nDevID Module successfully inserted LDevID key with key index {key_index}.\n')


@insert.command(name='ldevid-certificate')
@click.argument('file_path', required=True, type=click.Path(exists=True))
def insert_ldevid_certificate(file_path: Path) -> None:
    """Inserts an LDevID Certificate.

    Args:
        file_path: File path to the certificate file.
    """
    file_path = Path(file_path)
    devid_module = get_initialized_devid_module()
    if devid_module is None:
        return

    with file_path.open('rb') as f:
        key_bytes = f.read()

    # TODO(AlexHx8472): Exception handling
    try:
        certificate_serializer = CertificateSerializer(key_bytes)
        certificate_index = devid_module.insert_ldevid_certificate(certificate_serializer)
    except Exception as exception:  # noqa: BLE001
        click.echo(f'\n{exception}\n')
        return

    click.echo(f'\nDevID Module successfully inserted LDevID certificate with certificate index {certificate_index}.\n')


@insert.command(name='ldevid-certificate-chain')
@click.option(
    '--certificate-index',
    '-i',
    required=True,
    type=int,
    help='Certificate index corresponding to the certificate chain.',
)
@click.argument('file_path', required=True, type=click.Path(exists=True))
def insert_ldevid_certificate_chain(certificate_index: int, file_path: Path) -> None:
    """Inserts an LDevID Private Key.

    Args:
        certificate_index: The certificate index of the certificate matching the certificate chain.
        file_path: The file path to the certificate chain file.
    """
    file_path = Path(file_path)
    devid_module = get_initialized_devid_module()
    if devid_module is None:
        return

    with file_path.open('rb')as f:
        certificate_chain_bytes = f.read()

    # TODO(AlexHx8472): Exception handling
    try:
        certificate_chain_serializer = CertificateCollectionSerializer(certificate_chain_bytes)
        devid_module.insert_ldevid_certificate_chain(certificate_index, certificate_chain_serializer)
    except Exception as exception:  # noqa: BLE001
        click.echo(f'\n{exception}\n')
        return

    click.echo(f'\nDevID Module successfully inserted LDevID key with key index {certificate_index}.\n')


# ------------------------------------------------------- delete -------------------------------------------------------


@cli.group()
def delete() -> None:
    """Delete LDevID Keys, Certificates and Certificate Chains."""


@delete.command(name='devid-key')
@click.option('--key-index', '-i', required=True, type=int, help='Deletes the key and all corresponding certificates.')
def delete_devid_key(key_index: int) -> None:
    """Delete an LDevID Private Key.

    Args:
        key_index: The key index of the key to be deleted.
    """
    devid_module = get_initialized_devid_module()

    # TODO(AlexHx8472): Exception handling
    try:
        devid_module.delete_ldevid_key(key_index)
    except Exception as exception:  # noqa: BLE001
        click.echo(f'\n{exception}\n')

    click.echo(f'\nKey with key index {key_index} and all corresponding certificates successfully deleted.\n')


@delete.command(name='devid-certificate')
@click.option(
    '--certificate-index',
    '-i',
    required=True,
    type=int,
    help='Deletes the corresponding certificate and chain, if any.',
)
def delete_devid_certificate(certificate_index: int) -> None:
    """Delete an LDevID Certificate.

    Args:
        certificate_index: The certificate index of the certificate to be deleted.
    """
    devid_module = get_initialized_devid_module()

    # TODO(AlexHx8472): Exception handling
    try:
        devid_module.delete_ldevid_certificate(certificate_index)
    except Exception as exception:  # noqa: BLE001
        click.echo(f'\n{exception}\n')

    click.echo(f'\nCertificate and chain with index {certificate_index} successfully deleted.\n')


@delete.command(name='devid-certificate-chain')
@click.option(
    '--certificate-index',
    '-i',
    required=True,
    type=int,
    help='Deletes the certificate chain corresponding to the certificate index provided.',
)
def delete_devid_certificate_chain(certificate_index: int) -> None:
    """Delete an LDevID Certificate Chain.

    Args:
        certificate_index: The certificate index of the certificate that contains the certificate chain to be deleted.
    """
    devid_module = get_initialized_devid_module()

    # TODO(AlexHx8472): Exception handling
    try:
        devid_module.delete_ldevid_certificate_chain(certificate_index)
    except Exception as exception:  # noqa: BLE001
        click.echo(f'\n{exception}\n')

    click.echo(f'\nCertificate chain for certificate index {certificate_index} successfully deleted.\n')


# ------------------------------------------------------- enable -------------------------------------------------------


@cli.group()
def enable() -> None:
    """Enable DevID Keys and Certificates."""


@enable.command(name='devid-key')
@click.option('--key-index', '-i', required=True, type=int, help='Enables the key with the given index.')
def enable_devid_key(key_index: int) -> None:
    """Enable DevID Keys.

    Args:
        key_index: The key index of the key to be enabled.
    """
    devid_module = get_initialized_devid_module()

    # TODO(AlexHx8472): Exception handling
    try:
        devid_module.enable_devid_key(key_index)
    except Exception as exception:  # noqa: BLE001
        click.echo(f'\n{exception}\n')

    click.echo(f'\nKey with key index {key_index} successfully enabled.\n')


@enable.command(name='devid-certificate')
@click.option(
    '--certificate-index', '-i', required=True, type=int, help='Enables the certificate with the given index.'
)
def enable_devid_certificate(certificate_index: int) -> None:
    """Enable DevID Keys.

    Args:
        certificate_index: The certificate index of the certificate to be enabled.
    """
    devid_module = get_initialized_devid_module()

    # TODO(AlexHx8472): Exception handling
    try:
        devid_module.enable_devid_certificate(certificate_index)
    except Exception as exception:  # noqa: BLE001
        click.echo(f'\n{exception}\n')

    click.echo(f'\nCertificate with certificate index {certificate_index} successfully enabled.\n')


# ------------------------------------------------------- disable ------------------------------------------------------


@cli.group()
def disable() -> None:
    """Disable DevID Keys and Certificates."""


@disable.command(help='Disable DevID Keys.', name='devid-key')
@click.option('--key-index', '-i', required=True, type=int, help='Disables the key with the given index.')
def disable_devid_key(key_index: int) -> None:
    """Disables the DevID key corresponding to the provided key index.

    Args:
        key_index: The key index of the key to be disabled.
    """
    devid_module = get_initialized_devid_module()

    # TODO(AlexHx8472): Exception Handling
    try:
        devid_module.disable_devid_key(key_index)
    except Exception as exception:  # noqa: BLE001
        click.echo(f'\n{exception}\n')

    click.echo(f'\nKey with key index {key_index} successfully disabled.\n')


@disable.command(help='Disable DevID Keys.', name='devid-certificate')
@click.option(
    '--certificate-index', '-i', required=True, type=int, help='Disables the certificate with the given index.'
)
def disable_devid_certificate(certificate_index: int) -> None:
    """Disables the DevID certificate corresponding to the provided certificate index.

    Args:
        certificate_index: The certificate index of the certificate to be disabled.
    """
    devid_module = get_initialized_devid_module()

    # TODO(AlexHx8472): Exception handling
    try:
        devid_module.disable_devid_certificate(certificate_index)
    except Exception as exception:  # noqa: BLE001
        click.echo(f'\n{exception}\n')

    click.echo(f'\nCertificate with certificate index {certificate_index} successfully disabled.\n')
