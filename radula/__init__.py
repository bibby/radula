import sys
import argparse
import logging
from rad import Radula, RadulaError, RadulaClient
from proxy import RadulaProxy

from ._version import get_versions

__version__ = get_versions()['version']
del get_versions

logging.basicConfig(level=logging.INFO)

# ACL commands
cmd_acl = [
    'get-acl',
    'compare-acl',
    'sync-acl'
]

# User grant commands
cmd_usr = [
    'allow', 'allow-user',
    'disallow', 'disallow-user'
]

# Proxy commands
cmd_proxy = [
    'mb', 'make-bucket',
    'rb', 'remove-bucket',
    'lb', 'list-buckets',
    'put', 'up', 'upload',
    'get', 'dl', 'download',
    'mpl', 'mp-list', 'multipart-list',
    'mpc', 'mp-clean', 'multipart-clean',
    'rm', 'remove',
    'keys', 'info',
    'local-md5', 'remote-md5', 'verify'
]


def _real_main():
    args = _parse_args()
    if args.version:
        print __version__
        exit()

    command = args.command.replace('-', '_')

    if args.command in cmd_acl:
        radu = Radula()
        radu.connect(profile=args.profile)
        getattr(radu, command)(**vars(args))
        exit()

    if args.command in cmd_usr:
        radu = Radula()
        radu.connect(profile=args.profile)
        getattr(radu, command)(**vars(args))
        exit()

    if args.command in cmd_proxy:
        radu = RadulaProxy(profile=args.profile)
        getattr(radu, command)(**vars(args))
        pass


def check_negative(value):
    int_value = int(value)
    if int_value < 0:
        raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
    return int_value


def _parse_args():
    args = argparse.ArgumentParser(description='RadosGW client')
    commands = cmd_acl + cmd_usr + cmd_proxy

    args.add_argument(
        '--version',
        dest='version',
        action='store_true',
        help='Prints version number'
    )

    args.add_argument(
        '-r', '--read',
        dest='acl_read',
        action='store_true',
        help='During a user grant, permission includes reads'
    )

    args.add_argument(
        '-w', '--write',
        dest='acl_write',
        action='store_true',
        help='During a user grant, permission includes writes'
    )

    default_threads = RadulaClient.DEFAULT_UPLOAD_THREADS
    args.add_argument(
        '-t', '--threads',
        dest='threads',
        default=default_threads,
        help='Number of threads to use for uploads. Default={0}'.format(default_threads)
    )

    args.add_argument(
        '-p', '--profile',
        dest='profile',
        help='Boto profile. Overrides AWS_PROFILE environment var'
    )

    args.add_argument(
        '-f', '--force',
        dest='force',
        action='store_true',
        help='Overwrite local files without confirmation'.format(default_threads)
    )

    args.add_argument(
        '-y', '--verify',
        dest='verify',
        action='store_true',
        help='Verify uploads after they complete'.format(default_threads)
    )

    args.add_argument(
        'command',
        nargs='?',
        help='command',
        choices=commands
    )

    args.add_argument(
        'subject',
        nargs='?',
        action='store',
        help='Subject'
    )

    args.add_argument(
        'target',
        nargs='?',
        action='store',
        help='Target'
    )

    options = args.parse_args(sys.argv[1:])
    if not options.command and not options.version:
        args.print_help()
        exit()
    return options


def main():
    try:
        _real_main()
    except KeyboardInterrupt:
        sys.exit('\nERROR: Interrupted by user')
    except RadulaError as e:
        print "Error:", e.message
        exit(1)

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
