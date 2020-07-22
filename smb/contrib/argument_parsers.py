from argparse import ArgumentParser, Namespace, Action
from typing import Tuple
from re import compile as re_compile, search as re_search, I as RE_I


_NT_HASH_PATTERN = re_compile(pattern=r'^[0-9a-f]{32}$', flags=RE_I)


def _username_is_prefixed(username: str) -> bool:
    """
    Check whether a username is prefixed with a domain.

    :param username: The username which to check.
    :return: Whether the username is prefixed with a domain.
    """

    return bool(re_search(r'^[^\\]+\\', username))


def _partition_ad_username(username: str, separator: str = '\\') -> Tuple[str, str]:
    """
    Partition an Active Directory username into a domain part and a username part.

    :param username: The Active Directory username to be partitioned.
    :param separator: The separator that divides the domain part from the username part.
    :return: A tuple with the domain part and the username part.
    """
    if _username_is_prefixed(username):
        ad_domain, unprefixed_username = username.split(sep=separator, maxsplit=1)
    else:
        unprefixed_username = username
        ad_domain = ''

    return ad_domain, unprefixed_username


class _ParseNTHashAction(Action):
    def __call__(self, parser: ArgumentParser, namespace: Namespace, nt_hash: str, option_string: str = None):
        """
        Verify that the NT hash is conformant.
        """

        if not _NT_HASH_PATTERN.search(nt_hash):
            parser.error(f'Invalid NT hash ({nt_hash})')

        setattr(namespace, self.dest, nt_hash)


class _ParseADUsernameAction(Action):
    def __call__(self, parser: ArgumentParser, namespace: Namespace, username: str, option_string: str = None):
        """
        Split the AD username into a domain part and a username part.
        """

        namespace.domain, namespace.username = _partition_ad_username(username)


class SmbConnectionArgumentParser(ArgumentParser):
    def __init__(self):
        super().__init__()

        self.add_argument(
            '-w', '--timeout',
            help='The number of seconds the SMB connection should wait for packets before timing out.',
            type=int,
            default=5
        )

        self.add_argument(
            '--local-auth',
            help='Authenticate to the SMB server using system local credentials.',
            dest='local_auth',
            action='store_true',
            default=False
        )


class SmbSingleAuthenticationArgumentParser(SmbConnectionArgumentParser):
    def __init__(self):
        super().__init__()

        self.add_argument(
            'username',
            help='The username with which to authenticate with the SMB server. The format should be '
                 '\"DOMAIN\\USERNAME\" if authenticating via Active Directory.',
            type=str,
            metavar='USERNAME',
            action=_ParseADUsernameAction
        )

        credentials_group = self.add_mutually_exclusive_group(required=True)

        credentials_group.add_argument(
            '-p', '--password',
            help='A password with which to authenticate with the SMB server.',
            dest='password',
            metavar='PASSWORD',
            type=str,
            default=''
        )

        credentials_group.add_argument(
            '-H', '--nt-hash',
            help='An NT hash with which to authenticate with SMB server.',
            dest='nt_hash',
            metavar='NT_HASH',
            type=str,
            default='',
            action=_ParseNTHashAction
        )

    @staticmethod
    def verify_parsed_args(main_parser: ArgumentParser, parsed_args: Namespace) -> None:

        if parsed_args.domain == '' and not parsed_args.local_auth:
            main_parser.error(
                'An Active Directory domain must be specified in the username when not authenticating to the SMB '
                'server’s system locally using the `--local-auth` flag.'
            )

        if parsed_args.domain != '' and parsed_args.local_auth:
            main_parser.error(
                'An Active Directory domain should not be provided when authenticating to the SMB server’s system '
                ' locally using the `--local-auth` flag.'
            )
