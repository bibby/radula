import sys
import errno
import argparse
import logging
from rad import Radula, RadulaError, RadulaClient, config_check
from proxy import RadulaProxy
from ._version import get_versions

__version__ = get_versions()['version']
del get_versions

# ACL commands
cmd_acl = [
    'acls',
    'get-acl',
    'set-acl',
    'compare-acl',
    'sync-acl',
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
    'keys', 'info', 'size', 'etag',
    'remote-md5', 'remote-rehash', 'verify',
    'sc', 'streaming-copy', 'cat'
]

# commands to perform without a s3 connection
cmd_preconnect = [
    'local-md5',
    'profiles',
]


def _real_main():
    args = _parse_args()
    if args.version:
        print __version__
        exit()

    command = args.command.replace('-', '_')
    config_check()
    radu = Radula()

    log_level = logging.INFO
    if args.log_level:
        if not isinstance(args.log_level, int):
            level = getattr(logging, args.log_level)
            if isinstance(log_level, int):
                log_level = level

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s %(levelname)s:%(name)s: %(message)s'
    )
    logger = logging.getLogger("radula")
    logger.debug("Log Level: %d", log_level)

    if args.command in cmd_acl:
        radu.connect(profile=args.profile)
        getattr(radu, command)(**vars(args))
        exit()

    if args.command in cmd_proxy:
        radu = RadulaProxy(profile=args.profile)
        getattr(radu, command)(**vars(args))
        pass

    if args.command in cmd_preconnect:
        getattr(radu, command)(**vars(args))
        pass


def check_negative(value):
    int_value = int(value)
    if int_value < 0:
        msg = "%s is an invalid positive int value" % value
        raise argparse.ArgumentTypeError(msg)
    return int_value


def _parse_args(arg_string=None):
    args = argparse.ArgumentParser(description='RadosGW client')
    commands = cmd_acl + cmd_proxy + cmd_preconnect

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

    default_threads = RadulaClient.DEFAULT_THREADS
    thread_help = 'Number of threads to use for uploads. Default={0}'
    args.add_argument(
        '-t', '--threads',
        dest='threads',
        default=default_threads,
        help=thread_help.format(default_threads)
    )

    args.add_argument(
        '-p', '--profile',
        dest='profile',
        help='Boto profile. Overrides AWS_PROFILE environment var'
    )

    args.add_argument(
        '-d', '--destination',
        dest='destination',
        help='Destination boto profile, required for streaming copy'
    )

    args.add_argument(
        '-f', '--force',
        dest='force',
        action='store_true',
        help='Overwrite local files without confirmation'
    )

    args.add_argument(
        '-y', '--verify',
        dest='verify',
        action='store_true',
        help='Verify uploads after they complete. Uses --threads. When passed a destination profile, download and hash keys on both ends'
    )

    args.add_argument(
        '-c', '--chunk',
        dest='chunk_size',
        help='multipart upload chunk size in bytes.'
    )

    args.add_argument(
        '-l', '--long-keys',
        dest='long_key',
        action='store_true',
        help='prepends bucketname to key results.'
    )

    args.add_argument(
        '-L', '--log-level',
        dest='log_level',
        default=logging.INFO,
        help='Log level, [DEBUG, 10, INFO, 20, etc]'
    )

    args.add_argument(
        '-n', '--dry-run',
        dest='dry_run',
        action='store_true',
        help='Print would-be deletions without deleting'
    )

    args.add_argument(
        '-z', '--resume',
        dest='resume',
        action='store_true',
        help='Resume uploads if needed.'
    )

    args.add_argument(
        '-e', '--encrypt',
        dest='encrypt',
        action='store_true',
        default=None,
        help='Store content encrypted at rest'
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

    args.add_argument(
        'remainder',
        nargs=argparse.REMAINDER,
        action='store',
        help='Additional targets for supporting commands. See README'
    )

    options = args.parse_args(arg_string or sys.argv[1:])
    if not options.command and not options.version:
        args.print_help()
        exit()
    return options


def main():
    try:
        _real_main()
    except KeyboardInterrupt:
        sys.exit('\nERROR: Interrupted by user')
    except IOError as e:
        if e.errno != errno.EPIPE:
            # swallow SIGPIPE, so that piping this command's output
            # to 'head' or similar won't spoil stderr
            raise
    except RadulaError as e:
        print "Error:", e.message
        exit(1)
