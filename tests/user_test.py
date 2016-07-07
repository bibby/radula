import os
import sys

import boto
from nose.tools import assert_in, assert_not_in, raises
from moto import mock_s3
from radula import RadulaProxy, _parse_args, Radula, RadulaError


TEST_BUCKET = "tests"
here = os.path.dirname(os.path.realpath(__file__))
TEST_FILE = os.path.join(here, "data.txt")
REMOTE_FILE = os.path.join(TEST_BUCKET, os.path.basename(TEST_FILE))
PRIMARY_USER = 'test-user'
ALT_USER = 'alt-user'

aws_url = "http://acs.amazonaws.com/groups/global"
aws_auth = aws_url + "/AuthenticatedUsers"
aws_all = aws_url + "/AllUsers"


def test_allow_user():
    methods = ['allow', 'allow-user']
    remote_base = os.path.basename(REMOTE_FILE)
    read_key_messages = [
        "granting READ to {0} on key {1}",
        "granting READ_ACP to {0} on key {1}",
    ]
    read_key_messages = [m.format(ALT_USER, remote_base)
                         for m in read_key_messages]

    write_key_messages = [
        "granting WRITE to {0} on key {1}",
        "granting WRITE_ACP to {0} on key {1}",
    ]
    write_key_messages = [m.format(ALT_USER, remote_base)
                          for m in write_key_messages]

    read_bucket_messages = [
        "granting READ to {0} on bucket {1}",
        "granting READ_ACP to {0} on bucket {1}",
    ]
    read_bucket_messages = [m.format(ALT_USER, TEST_BUCKET)
                            for m in read_bucket_messages]

    write_bucket_messages = [
        "granting WRITE to {0} on bucket {1}",
        "granting WRITE_ACP to {0} on bucket {1}",
    ]
    write_bucket_messages = [m.format(ALT_USER, TEST_BUCKET)
                             for m in write_bucket_messages]
    key_messages = read_key_messages + write_key_messages
    bucket_messages = read_bucket_messages + write_bucket_messages

    test_sets = (
        (REMOTE_FILE, '', read_key_messages,
         write_key_messages + bucket_messages),
        (REMOTE_FILE, '-r', read_key_messages,
         write_key_messages + bucket_messages),
        (REMOTE_FILE, '-w', write_key_messages,
         read_key_messages + bucket_messages),
        (REMOTE_FILE, '-rw', key_messages, bucket_messages),
        (REMOTE_FILE, '-r -w', key_messages, bucket_messages),
        (TEST_BUCKET, '', read_bucket_messages, write_bucket_messages),
        (TEST_BUCKET, '-r', read_bucket_messages, write_bucket_messages),
        (TEST_BUCKET, '-rw', read_bucket_messages + write_bucket_messages, []),
        (TEST_BUCKET, '-w', write_bucket_messages, read_bucket_messages),
        (TEST_BUCKET, '-r -w', read_bucket_messages + write_bucket_messages, []),
    )
    for test_set in test_sets:
        for method in methods:
            yield allow_user, method, test_set


@mock_s3
def allow_user(method, test_set):
    subject, flags, expected, unexpected = test_set

    conn = boto.connect_s3()
    proxy = RadulaProxy(connection=conn)
    radu = Radula(connection=conn)
    proxy.make_bucket(subject=TEST_BUCKET)

    # give something to download
    args = vars(_parse_args(['up']))
    args.update({
        "subject": TEST_FILE,
        "target": subject
    })
    proxy.upload(**args)
    sys.stdout.truncate(0)

    flags = flags.split(' ')
    args = [arg for arg in flags + [method, ALT_USER, subject] if arg]
    args = vars(_parse_args(args))
    getattr(radu, args.get("command").replace('-', '_'))(**args)
    out = [line.strip() for line in sys.stdout.getvalue().split("\n")]
    sys.stdout.truncate(0)

    for msg in expected:
        errmsg = "Expecting log message containing '{0}'".format(msg)
        if msg not in out:
            p = 1
        assert_in(msg, out, msg=errmsg)

    for msg in unexpected:
        errmsg = "Not expecting log message containing '{0}'".format(msg)
        assert_not_in(msg, out, msg=errmsg)


def test_get_acl():
    test_sets = (
        (
            TEST_BUCKET,
            [
                'ACL for bucket: ' + TEST_BUCKET,
                '[CanonicalUser:OWNER] None = FULL_CONTROL'
            ],
            [
                'ACL for key'
            ]
        ),
        (
            REMOTE_FILE,
            [
                'ACL for key: ' + os.path.basename(REMOTE_FILE)
            ],
            [
                'ACL for bucket'
            ]
        )
    )
    for test_set in test_sets:
        yield get_acl_subject, test_set


@mock_s3
def get_acl_subject(test_set):
    subject, expected, unexpected = test_set
    conn = boto.connect_s3()
    proxy = RadulaProxy(connection=conn)
    radu = Radula(connection=conn)
    proxy.make_bucket(subject=TEST_BUCKET)

    # give something to download
    args = vars(_parse_args(['up']))
    args.update({
        "subject": TEST_FILE,
        "target": subject
    })
    proxy.upload(**args)
    sys.stdout.truncate(0)

    args = vars(_parse_args(['get-acl', subject]))
    radu.get_acl(**args)
    out = [line.strip() for line in sys.stdout.getvalue().split("\n")]
    sys.stdout.truncate(0)

    for msg in expected:
        errmsg = "Expecting log message containing '{0}'".format(msg)
        assert_in(msg, out, msg=errmsg)

    for msg in unexpected:
        errmsg = "Not expecting log message containing '{0}'".format(msg)
        assert_not_in(msg, out, msg=errmsg)


def test_bad_acls():
    for bad in ['public', '', 'made_up']:
        yield set_acl_canned_fail, bad


@mock_s3
@raises(RadulaError)
def set_acl_canned_fail(acl):
    conn = boto.connect_s3()
    proxy = RadulaProxy(connection=conn)
    radu = Radula(connection=conn)
    proxy.make_bucket(subject=TEST_BUCKET)

    # give something to download
    args = vars(_parse_args(['up']))
    args.update({
        "subject": TEST_FILE,
        "target": REMOTE_FILE
    })
    proxy.upload(**args)
    sys.stdout.truncate(0)

    args = vars(_parse_args(['set-acl', REMOTE_FILE, acl]))
    radu.set_acl(**args)


def test_set_acl():
    key_name = os.path.basename(REMOTE_FILE)
    test_sets = {
        'private': [
            (
                TEST_BUCKET,
                [
                    'Bucket ACL for: ' + TEST_BUCKET,
                    '[CanonicalUser:OWNER] None = FULL_CONTROL',
                ],
                [
                    'ACL for key'
                ]
            ),
            (
                REMOTE_FILE,
                [
                    'ACL for key: ' + key_name
                ],
                [
                    'ACL for bucket',
                    '[Group] {0} = READ'.format(aws_all),
                    "Setting bucket's ACL on " + key_name,
                ]
            )
        ],
        'public-read': [
            (
                TEST_BUCKET,
                [
                    'Bucket ACL for: ' + TEST_BUCKET,
                    '[CanonicalUser:OWNER] None = FULL_CONTROL',
                    '[Group] {0} = READ'.format(aws_all),
                    "Setting bucket's ACL on " + key_name,
                ],
                [
                    'ACL for key',
                ]
            ),
            (
                REMOTE_FILE,
                [
                    'ACL for key: ' + key_name,
                    '[CanonicalUser:OWNER] None = FULL_CONTROL',
                    '[Group] {0} = READ'.format(aws_all),
                ],
                [
                    'ACL for bucket',
                ]
            )
        ],
        'public-read-write': [
            (
                TEST_BUCKET,
                [
                    'Bucket ACL for: ' + TEST_BUCKET,
                    '[CanonicalUser:OWNER] None = FULL_CONTROL',
                    '[Group] {0} = WRITE'.format(aws_all),
                    "Setting bucket's ACL on " + key_name,
                ],
                [
                    'ACL for key',
                ]
            ),
            (
                REMOTE_FILE,
                [
                    'ACL for key: ' + key_name,
                    '[CanonicalUser:OWNER] None = FULL_CONTROL',
                    '[Group] {0} = WRITE'.format(aws_all),
                ],
                [
                    'ACL for bucket',
                ]
            )
        ],
        'authenticated-read': [
            (
                TEST_BUCKET,
                [
                    'Bucket ACL for: ' + TEST_BUCKET,
                    '[CanonicalUser:OWNER] None = FULL_CONTROL',
                    '[Group] {0} = READ'.format(aws_auth),
                    "Setting bucket's ACL on " + key_name,
                ],
                [
                    'ACL for key',
                ]
            ),
            (
                REMOTE_FILE,
                [
                    'ACL for key: ' + key_name,
                    '[CanonicalUser:OWNER] None = FULL_CONTROL',
                    '[Group] {0} = READ'.format(aws_auth),
                ],
                [
                    'ACL for bucket',
                ]
            )
        ],
    }
    for acl in test_sets.keys():
        for test_set in test_sets.get(acl):
            yield set_acl_subject, test_set, acl


@mock_s3
def set_acl_subject(test_set, acl):
    subject, expected, unexpected = test_set
    conn = boto.connect_s3()
    proxy = RadulaProxy(connection=conn)
    radu = Radula(connection=conn)
    proxy.make_bucket(subject=TEST_BUCKET)

    # give something to download
    args = vars(_parse_args(['up']))
    args.update({
        "subject": TEST_FILE,
        "target": subject
    })
    proxy.upload(**args)
    sys.stdout.truncate(0)

    args = vars(_parse_args(['set-acl', subject, acl]))
    radu.set_acl(**args)
    out = [line.strip() for line in sys.stdout.getvalue().split("\n")]
    sys.stdout.truncate(0)

    for msg in expected:
        errmsg = "Expecting log message containing '{0}'".format(msg)
        assert_in(msg, out, msg=errmsg)

    for msg in unexpected:
        errmsg = "Not expecting log message containing '{0}'".format(msg)
        assert_not_in(msg, out, msg=errmsg)


def compare_acl_test():
    key_name = os.path.basename(REMOTE_FILE)
    test_sets = (
        (
            'private',
            REMOTE_FILE,
            [
                'Bucket ACL for: ' + TEST_BUCKET,
                '[CanonicalUser:OWNER] None = FULL_CONTROL',
                'Keys with identical ACL: 1',
                'Keys with different ACL: 0'
            ],
            [
                'Difference in {0}:'.format(key_name),
            ]
        ),
        (
            'public-read-write',
            REMOTE_FILE,
            [
                'Bucket ACL for: ' + TEST_BUCKET,
                '[CanonicalUser:OWNER] None = FULL_CONTROL',
                'Difference in {0}:'.format(key_name),
                'Keys with identical ACL: 0',
                'Keys with different ACL: 1',
                '[Group] {0} = WRITE'.format(aws_all),
            ],
            []
        ),
    )

    for test_set in test_sets:
        yield compare_acl, test_set


@mock_s3
def compare_acl(test_set):
    acl, subject, expected, unexpected = test_set
    conn = boto.connect_s3()
    proxy = RadulaProxy(connection=conn)
    radu = Radula(connection=conn)
    bucket = conn.create_bucket(TEST_BUCKET)

    # give something to download
    args = vars(_parse_args(['up']))
    args.update({
        "subject": TEST_FILE,
        "target": REMOTE_FILE
    })
    proxy.upload(**args)
    # for sake of testing, ensure equality
    key_name = os.path.basename(REMOTE_FILE)
    key = bucket.get_key(key_name)
    key.set_canned_acl(acl)

    args = vars(_parse_args(['compare-acl', subject, acl]))
    radu.compare_acl(**args)
    out = [line.strip() for line in sys.stdout.getvalue().split("\n")]
    sys.stdout.truncate(0)

    for msg in expected:
        errmsg = "Expecting log message containing '{0}'".format(msg)
        assert_in(msg, out, msg=errmsg)

    for msg in unexpected:
        errmsg = "Not expecting log message containing '{0}'".format(msg)
        assert_not_in(msg, out, msg=errmsg)
