from prettytable import PrettyTable

from trustpoint_devid_module.serializer import (
    PrivateKeySerializer,
    CertificateSerializer,
    CertificateCollectionSerializer
)
from trustpoint_devid_module.service_interface import DevIdModule

import click

from trustpoint_devid_module.util import WORKING_DIR

def get_devid_module() -> DevIdModule:
    return DevIdModule(WORKING_DIR)

def get_initialized_devid_module() -> None | DevIdModule:
    devid_module = DevIdModule(WORKING_DIR)
    if devid_module.inventory is None:
        click.echo('DevID Module is not yet initialized.')
        return None
    return devid_module

@click.group(help="Trustpoint DevID Module")
def cli() -> None:
    pass

@cli.command(help='Status information about the DevID Module.')
def status() -> None:
    devid_module = get_devid_module()
    if devid_module.inventory:
        click.echo(f'\nDevID Module is initialized with working directory: {devid_module.working_dir}.\n')
        return
    click.echo('\nDevID Module is not yet initialized.\n')

@cli.command(help=f'Initializes the DevID Module.')
def initialize() -> None:
    devid_module = get_devid_module()
    if devid_module.inventory:
        click.echo(f'\nDevID Module is already initialized with working directory: {devid_module.working_dir}.\n')
        return

    devid_module.initialize()
    click.echo('\nDevID Module successfully initialized.\n')


@cli.command(help='Purges all stored data and secrets.')
def purge() -> None:
    devid_module = get_devid_module()
    if devid_module.inventory is None:
        click.echo('\nDevID Module is not yet initialized, nothing to purge.\n')
        return

    if click.confirm('\nAre you sure to purge the DevID Module? This will irreversibly delete all data and secrets!\n'):
        devid_module.purge()
        click.echo('\nDevID Module successfully purged.\n')

# ----------------------------------------------------- enumerate ------------------------------------------------------

@cli.group(help='Lists LDevID Keys, Certificates and Certificate Chains.', name='enumerate')
def enumerate_() -> None:
    pass

@enumerate_.command(help='Lists all DevID public keys.')
def devid_public_keys() -> None:
    devid_module = get_devid_module()
    table = PrettyTable()
    table.field_names = ['Key Index', 'Is Enabled', 'Subject Public Key Info', 'Is IDevID']
    table.add_rows(devid_module.enumerate_devid_public_keys())
    click.echo(f'\n{table}\n')

def format_certificate_enumeration(
        devid_certificates_enumeration: list[tuple[int, int, bool, bool, bytes]]
) -> list[tuple[int, int, bool, bool]]:
    new_enumeration = []
    for entry in devid_certificates_enumeration:
        new_enumeration.append(
            (entry[0], entry[1], entry[2], entry[3])
        )
    return new_enumeration

def format_certificate_enumeration_with_certificates(
        devid_certificates_enumeration: list[tuple[int, int, bool, bool, bytes]]
) -> list[tuple[int, int, bool, bool, str]]:
    new_enumeration = []
    for entry in devid_certificates_enumeration:
        new_enumeration.append(
            (entry[0], entry[1], entry[2], entry[3], CertificateSerializer(entry[4]).as_pem().decode())
        )
    return new_enumeration

@enumerate_.command(help='Lists all DevID public keys.')
@click.option('--show-certificates', '-s', required=False, default=False, is_flag=True)
def devid_certificates(show_certificates: bool) -> None:
    devid_module = get_devid_module()
    table = PrettyTable()
    if show_certificates:
        table.field_names = ['Certificate Index', 'Key Index', 'Is Enabled', 'Is IDevID', 'Certificate']
        table.add_rows(format_certificate_enumeration_with_certificates(devid_module.enumerate_devid_certificates()))
    else:
        table.field_names = ['Certificate Index', 'Key Index', 'Is Enabled', 'Is IDevID']
        table.add_rows(format_certificate_enumeration(devid_module.enumerate_devid_certificates()))
    click.echo(f'\n{table}\n')

@enumerate_.command(help='Lists all DevID certificates contained in the chain.')
@click.option('--certificate-index', '-i', required=True, type=int, help='The corresponding certificate index.')
def devid_certificate_chains(certificate_index: int) -> None:
    devid_module = get_devid_module()
    devid_certificate_ = devid_module.inventory.devid_certificates.get(certificate_index)
    if devid_certificate_ is None:
        click.echo(f'\nNo DevID certificate found with the given index {certificate_index}.\n')
        return
    if not devid_certificate_.certificate_chain:
        click.echo(
            f'\nDevID certificate with certificate index {certificate_index} '
            f'has no corresponding certificate chain stored.\n')
        return

    table = PrettyTable()
    table.field_names = ['# Certificate In Chain', 'Certificate']

    devid_certificate_chain = [
        CertificateSerializer(certificate).as_pem().decode() for certificate in devid_certificate_.certificate_chain]
    table.add_rows([entry for entry in enumerate(devid_certificate_chain)])
    click.echo(f'\n{table}\n')

# ------------------------------------------------------- insert -------------------------------------------------------

@cli.group(help='Insert LDevID Keys, Certificates and Certificate Chains.')
def insert() -> None:
    pass

@insert.command(help='Inserts an LDevID Private Key.')
@click.option('--password', '-p', default=None, required=False, help='Password, if the key file is encrypted.')
@click.option('--file-path', '-f', required=True, type=click.Path(exists=True), help='Path to the private key file.')
def ldevid_key(password: str, file_path: str) -> None:
    if password is not None:
        password = password.encode()
    devid_module = get_initialized_devid_module()
    if devid_module is None:
        return

    with open(file_path, 'rb') as f:
        key_bytes = f.read()

    try:
        key_serializer = PrivateKeySerializer(key_bytes, password)
        key_index = devid_module.insert_ldevid_key(key_serializer)
    except Exception as exception:
        click.echo(f'\n{exception}\n')
        return

    click.echo(f'\nDevID Module successfully inserted LDevID key with key index {key_index}.\n')

@insert.command(help='Inserts an LDevID Certificate.')
@click.option('--file-path', '-f', required=True, type=click.Path(exists=True), help='Path to the private key file.')
def ldevid_certificate(file_path: str) -> None:
    devid_module = get_initialized_devid_module()
    if devid_module is None:
        return

    with open(file_path, 'rb') as f:
        key_bytes = f.read()

    try:
        certificate_serializer = CertificateSerializer(key_bytes)
        certificate_index = devid_module.insert_ldevid_certificate(certificate_serializer)
    except Exception as exception:
        click.echo(f'\n{exception}\n')
        return

    click.echo(f'\nDevID Module successfully inserted LDevID certificate with certificate index {certificate_index}.\n')

@insert.command(help='Inserts an LDevID Private Key.')
@click.option(
    '--certificate-index', '-i',
    required=True,
    type=int,
    help='Certificate index corresponding to the certificate chain.')
@click.option(
    '--file-path', '-f',
    required=True,
    type=click.Path(exists=True),
    help='Path to the private key file.')
def ldevid_certificate_chain(certificate_index: int, file_path: str) -> None:
    devid_module = get_initialized_devid_module()
    if devid_module is None:
        return

    with open(file_path, 'rb') as f:
        certificate_chain_bytes = f.read()

    try:
        certificate_chain_serializer = CertificateCollectionSerializer(certificate_chain_bytes)
        devid_module.insert_ldevid_certificate_chain(certificate_index, certificate_chain_serializer)
    except Exception as exception:
        click.echo(f'\n{exception}\n')
        return

    click.echo(f'\nDevID Module successfully inserted LDevID key with key index {certificate_index}.\n')

# ------------------------------------------------------- delete -------------------------------------------------------

@cli.group(help='Delete LDevID Keys, Certificates and Certificate Chains.')
def delete() -> None:
    pass

@delete.command(help='Delete an LDevID Private Key.')
@click.option('--key-index', '-i', required=True, type=int, help='Deletes the key and all corresponding certificates.')
def devid_key(key_index: int) -> None:
    devid_module = get_initialized_devid_module()

    try:
        devid_module.delete_ldevid_key(key_index)
    except Exception as exception:
        click.echo(f'\n{exception}\n')

    click.echo(f'\nKey with key index {key_index} and all corresponding certificates successfully deleted.\n')


@delete.command(help='Delete an LDevID Certificate.')
@click.option('--certificate-index', '-i', required=True, type=int, help='Deletes the corresponding certificate and chain, if any.')
def devid_certificate(certificate_index: int) -> None:
    devid_module = get_initialized_devid_module()

    try:
        devid_module.delete_ldevid_certificate(certificate_index)
    except Exception as exception:
        click.echo(f'\n{exception}\n')

    click.echo(f'\nCertificate and chain with index {certificate_index} successfully deleted.\n')


@delete.command(help='Delete an LDevID Certificate Chain.')
@click.option(
    '--certificate-index', '-i',
    required=True,
    type=int,
    help='Deletes the certificate chain corresponding to the certificate index provided.')
def devid_certificate(certificate_index: int) -> None:
    devid_module = get_initialized_devid_module()

    try:
        devid_module.delete_ldevid_certificate_chain(certificate_index)
    except Exception as exception:
        click.echo(f'\n{exception}\n')

    click.echo(f'\nCertificate chain for certificate index {certificate_index} successfully deleted.\n')


# ------------------------------------------------------- enable -------------------------------------------------------

@cli.group(help='Enable DevID Keys and Certificates.')
def enable() -> None:
    pass

@enable.command(help='Enable DevID Keys.', name='devid-key')
@click.option('--key-index', '-i', required=True, type=int, help='Enables the key with the given index.')
def enable_devid_key(key_index: int) -> None:
    devid_module = get_initialized_devid_module()

    try:
        devid_module.enable_devid_key(key_index)
    except Exception as exception:
        click.echo(f'\n{exception}\n')

    click.echo(f'\nKey with key index {key_index} successfully enabled.\n')

@enable.command(help='Enable DevID Keys.', name='devid-certificate')
@click.option('--certificate-index', '-i', required=True, type=int, help='Enables the certificate with the given index.')
def enable_devid_certificate(certificate_index: int) -> None:
    devid_module = get_initialized_devid_module()

    try:
        devid_module.enable_devid_certificate(certificate_index)
    except Exception as exception:
        click.echo(f'\n{exception}\n')

    click.echo(f'\nCertificate with certificate index {certificate_index} successfully enabled.\n')

# ------------------------------------------------------- disable ------------------------------------------------------

@cli.group(help='Disable DevID Keys and Certificates.')
def disable() -> None:
    pass

@disable.command(help='Disable DevID Keys.', name='devid-key')
@click.option('--key-index', '-i', required=True, type=int, help='Disables the key with the given index.')
def disable_devid_key(key_index: int) -> None:
    devid_module = get_initialized_devid_module()

    try:
        devid_module.disable_devid_key(key_index)
    except Exception as exception:
        click.echo(f'\n{exception}\n')

    click.echo(f'\nKey with key index {key_index} successfully disabled.\n')

@disable.command(help='Disable DevID Keys.', name='devid-certificate')
@click.option('--certificate-index', '-i', required=True, type=int, help='Disables the certificate with the given index.')
def disable_devid_certificate(certificate_index: int) -> None:
    devid_module = get_initialized_devid_module()

    try:
        devid_module.disable_devid_certificate(certificate_index)
    except Exception as exception:
        click.echo(f'\n{exception}\n')

    click.echo(f'\nCertificate with certificate index {certificate_index} successfully disabled.\n')