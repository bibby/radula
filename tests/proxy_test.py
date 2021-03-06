import json
import os
import boto
from boto.exception import S3ResponseError
from moto import mock_s3
import sys
import logging
from radula import RadulaProxy, RadulaError, _parse_args, Radula
from nose.tools import (assert_equal, assert_true, raises,
                        assert_false, assert_in, assert_not_in)
from log_match import TestHandler, Matcher

TEST_BUCKET = "tests"
here = os.path.dirname(os.path.realpath(__file__))
TEST_FILE_NAME = "testdata.txt"
TEST_FILE = os.path.join(here, TEST_FILE_NAME)
REMOTE_FILE = os.path.join(TEST_BUCKET, os.path.basename(TEST_FILE))


def args_test():
    # ( input string, { expected output args } )
    test_sets = (
        (
            "local-md5 file",
            {
                "command": "local-md5",
                "subject": "file",
                "acl_read": False,
                "acl_write": False,
                "threads": Radula.DEFAULT_THREADS,
                "profile": None
            },
        ),
        (
            "-p alt_profile -rw allow friend mybucket",
            {
                "command": "allow",
                "subject": "friend",
                "target": "mybucket",
                "profile": "alt_profile",
                "force": False,
                "verify": False,
                "destination": None
            },
        ),
        (
            "-fy up file bucket/",
            {
                "command": "up",
                "subject": "file",
                "target": "bucket/",
                "profile": None,
                "force": True,
                "verify": True,
                "destination": None
            },
        ),
    )

    for i, o in test_sets:
        yield check_command, i, o


def check_command(input, output):
    args = vars(_parse_args(input.split(" ")))
    for prop in output:
        assert_equal(args.get(prop), output.get(prop))


@mock_s3
def test_make_bucket():
    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)
    out = sys.stdout.getvalue().strip()
    assert_equal('Created bucket: ' + TEST_BUCKET, out)


@mock_s3
@raises(RadulaError)
def test_make_bucket_fail():
    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject="")


def test_list_bucket():
    bucket_sets = (
        [],
        [TEST_BUCKET],
        [TEST_BUCKET, 'radus'],
        [TEST_BUCKET, 'radus', 'cephs'],
    )
    for method in ["lb", "list_buckets"]:
        for buckets in bucket_sets:
            yield list_method, method, buckets


@mock_s3
def list_method(method, buckets):
    radu = RadulaProxy(connection=boto.connect_s3())
    for bucket in buckets:
        radu.make_bucket(subject=bucket)
    sys.stdout.truncate(0)

    getattr(radu, method)()
    out = sys.stdout.getvalue().strip()
    assert_equal(sorted(buckets), sorted([b for b in out.split("\n") if b]))


def test_upload_fail():
    methods = ["up", "put", "upload"]
    # failure sets. subject or target, but not both; and neither
    test_sets = [
        {},
        {"subject": TEST_FILE},
        {"target": REMOTE_FILE}
    ]
    for method in methods:
        for test_set in test_sets:
            yield up_method_fail, method, test_set


@mock_s3
@raises(RadulaError)
def up_method_fail(method, test_set):
    radu = RadulaProxy(connection=boto.connect_s3())
    bucket = TEST_BUCKET
    radu.make_bucket(subject=bucket)
    sys.stdout.truncate(0)

    getattr(radu, method)(**test_set)


def test_upload_file():
    methods = ["up", "put", "upload"]
    test_sets = [
        {"subject": TEST_FILE,
         "target": REMOTE_FILE}
    ]
    for method in methods:
        for test_set in test_sets:
            yield up_method, method, test_set


@mock_s3
def up_method(method, test_set):
    handler = TestHandler(Matcher())
    logger = logging.getLogger()
    logger.addHandler(handler)

    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)
    sys.stdout.truncate(0)

    args = vars(_parse_args(["-y", method]))
    args.update(test_set)
    getattr(radu, args.get("command"))(**args)

    assert_false(handler.matches(levelno=logging.ERROR))
    assert_false(handler.matches(levelno=logging.WARNING))
    assert_true(handler.matches(levelno=logging.INFO))
    msgs = [
        "uploading",
        TEST_BUCKET + ".s3.amazonaws.com/" + TEST_FILE_NAME,
        "Checksum Verified!"
    ]

    fmt = "Expecting log message containing '{0}'"
    for msg in msgs:
        assert_true(
            handler.matches(message=msg),
            msg=fmt.format(msg)
        )


def test_download_fail():
    methods = ["dl", "get", "download"]
    test_sets = [
        {},
        {"target": TEST_FILE},
        {"subject": TEST_BUCKET},
    ]
    for method in methods:
        for test_set in test_sets:
            yield dl_method_fail, method, test_set


@mock_s3
@raises(RadulaError)
def dl_method_fail(method, test_set):
    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)

    # give something to download
    args = vars(_parse_args(['up']))
    args.update({
        "subject": TEST_FILE,
        "target": REMOTE_FILE
    })
    radu.upload(**args)
    sys.stdout.truncate(0)

    getattr(radu, method)(**test_set)


def test_download_file():
    methods = ['dl', 'get', 'download']
    test_sets = [
        {'subject': REMOTE_FILE,
         'target': TEST_FILE + '2'},
        {'subject': REMOTE_FILE},
        {'subject': REMOTE_FILE,
         'target': '/tmp/rad/' + os.path.basename(TEST_FILE) + '2'},
        {'subject': REMOTE_FILE,
         'target': 'tmp-rad/to/' + os.path.basename(TEST_FILE) + '2'},
        {'subject': REMOTE_FILE,
         'target': '/tmp/rad/',
         'expect': '/tmp/rad/' + os.path.basename(TEST_FILE),
        },
        {'subject': REMOTE_FILE,
         'target': 'tmp-rad/to/',
         'expect': 'tmp-rad/to/' + os.path.basename(TEST_FILE),
        },
    ]

    for method in methods:
        for test_set in test_sets:
            yield dl_method, method, test_set
            for d in ['tmp-rad/to', 'tmp-rad', '/tmp/rad']:
                if os.path.isdir(d):
                    os.rmdir(d)


@mock_s3
def dl_method(method, test_set):
    handler = TestHandler(Matcher())
    logger = logging.getLogger()
    logger.addHandler(handler)

    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)

    # give something to download
    args = vars(_parse_args(['up']))
    args.update({
        "subject": TEST_FILE,
        "target": REMOTE_FILE
    })
    radu.upload(**args)
    sys.stdout.truncate(0)

    args = vars(_parse_args([method]))
    args.update(test_set)
    args.update({"force": True})
    getattr(radu, args.get("command"))(**args)

    out = sys.stdout.getvalue().strip()
    msgs = [
        "Download Progress",
        "100.00%",
    ]

    for msg in msgs:
        fmt = "Expecting log message containing '{0}'".format(msg)
        assert_true(handler.matches(message=msg), msg=fmt.format(msg))

    target = test_set.get("target", TEST_FILE)
    if os.path.isdir(target):
        target = str(os.sep).join([target.rstrip(os.sep), os.path.basename(TEST_FILE)])

    assert_file = test_set.get('expect', target)
    logger.debug('PASSES = ' + str(os.path.isfile(assert_file)))
    logger.debug('EXPECT = ' + str(assert_file))
    assert_true(os.path.isfile(assert_file))
    if assert_file != TEST_FILE:
        os.remove(assert_file)


@mock_s3
@raises(S3ResponseError)
def keys_fail_test():
    RadulaProxy(connection=boto.connect_s3()).keys(subject=TEST_BUCKET)


@mock_s3
def key_test():
    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)

    # give something to download
    args = vars(_parse_args(['up']))
    expected = []
    for i in xrange(3):
        remote_file = REMOTE_FILE + str(i)
        expected.append(remote_file)
        args.update({
            "subject": TEST_FILE,
            "target": remote_file
        })
        radu.upload(**args)
    sys.stdout.truncate(0)

    radu.keys(subject=TEST_BUCKET)
    keys = [k.strip() for k in sys.stdout.getvalue().strip().split("\n")]

    for expected_key in expected:
        expected_key = os.path.basename(expected_key)
        msg = "Expecting output containing '{0}'".format(expected_key)
        assert_in(expected_key, keys, msg=msg)


@mock_s3
def key_glob_test():
    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)

    # give something to download
    args = vars(_parse_args(['up']))
    expected = []
    keys_added = 3
    # some to find
    for i in xrange(keys_added):
        remote_file = REMOTE_FILE + str(i)
        expected.append(remote_file)
        args.update({
            "subject": TEST_FILE,
            "target": remote_file
        })
        radu.upload(**args)

    # some to miss
    for i in xrange(keys_added):
        remote_file = os.path.join(TEST_BUCKET, "miss-" + str(i) + os.path.basename(TEST_FILE))
        args.update({
            "subject": TEST_FILE,
            "target": remote_file
        })
        radu.upload(**args)

    sys.stdout.truncate(0)

    radu.keys(subject=os.path.join(TEST_BUCKET, 'testdata*'))
    keys = [k.strip() for k in sys.stdout.getvalue().strip().split("\n")]
    for expected_key in expected:
        expected_key = os.path.basename(expected_key)
        msg = "Expecting output containing '{0}'".format(expected_key)
        assert_in(expected_key, keys, msg=msg)
    assert_equal(
        keys_added,
        len(keys),
        "Expected to have %d keys, got %d" % (keys_added, len(keys))
    )


@mock_s3
def key_slash_test():
    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)

    # give something to download
    args = vars(_parse_args(['up']))
    expected = []
    keys_added = 3
    # some to find
    for i in xrange(keys_added):
        remote_file = os.path.join(TEST_BUCKET, "find", os.path.basename(TEST_FILE)) + str(i)
        expected.append(remote_file)
        args.update({
            "subject": TEST_FILE,
            "target": remote_file
        })
        radu.upload(**args)

    # some to miss
    for i in xrange(keys_added):
        remote_file = os.path.join(TEST_BUCKET, "miss", os.path.basename(TEST_FILE)) + str(i)
        args.update({
            "subject": TEST_FILE,
            "target": remote_file
        })
        radu.upload(**args)

    sys.stdout.truncate(0)

    # bucket/find/ (trailing slash)
    radu.keys(subject=os.path.join(TEST_BUCKET, 'find', ''))
    keys = [k.strip() for k in sys.stdout.getvalue().strip().split("\n")]
    for expected_key in expected:
        expected_key = os.path.join('find', os.path.basename(expected_key))
        msg = "Expecting output containing '{0}'".format(expected_key)
        assert_in(expected_key, keys, msg=msg)
    assert_equal(
        keys_added,
        len(keys),
        "Expected to have %d keys, got %d" % (keys_added, len(keys))
    )


def rm_test():
    for method in ['rm', 'remove']:
        yield rm_method, method


@mock_s3
def rm_method(method):
    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)

    # give something to rm
    args = vars(_parse_args(['up']))
    expected = []
    for i in xrange(3):
        remote_file = REMOTE_FILE + str(i)
        expected.append(remote_file)
        args.update({
            "subject": TEST_FILE,
            "target": remote_file
        })
        radu.upload(**args)

    while len(expected):
        remove_file = expected.pop()
        sys.stdout.truncate(0)
        getattr(radu, method)(subject=remove_file)
        absent_key = os.path.basename(remove_file)
        keys = [k.strip() for k in sys.stdout.getvalue().strip().split("\n")]
        msg = "Expecting output containing '{0}'".format(absent_key)
        assert_in(absent_key, keys, msg=msg)
        sys.stdout.truncate(0)

        radu.keys(subject=TEST_BUCKET)
        keys = [k.strip() for k in sys.stdout.getvalue().strip().split("\n")]

        fmt = "Expecting absence of key mention '{0}'"
        assert_not_in(
            absent_key,
            keys,
            msg=fmt.format(absent_key))
        for expected_key in expected:
            expected_key = os.path.basename(expected_key)
            fmt = "Expecting output containing '{0}'"
            assert_in(
                expected_key,
                keys,
                msg=fmt.format(expected_key)
            )


@mock_s3
@raises(RadulaError)
def key_info_no_subject_test():
    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)
    radu.info()


@mock_s3
@raises(RadulaError)
def key_info_bad_subject_test():
    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)
    radu.info(subject=REMOTE_FILE)


@mock_s3
def key_info_test():
    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)

    # give something to info
    args = vars(_parse_args(['up']))
    remote_file = REMOTE_FILE
    args.update({
        "subject": TEST_FILE,
        "target": remote_file
    })
    radu.upload(**args)
    sys.stdout.truncate(0)
    radu.info(subject=REMOTE_FILE)

    out = sys.stdout.getvalue().strip()
    info = json.loads(out)[0]
    for k in ('key', 'info'):
        assert_in(k, info)
    key_info = info.get("info")
    for k in ('content_length', 'owner', 'size', 'bucket'):
        assert_in(k, key_info)
    assert_equal(key_info.get("bucket"), TEST_BUCKET)


@mock_s3
@raises(S3ResponseError)
def bucket_info_fail_test():
    RadulaProxy(connection=boto.connect_s3()).info(subject=TEST_BUCKET)


@mock_s3
def bucket_info_test():
    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)
    sys.stdout.truncate(0)
    radu.info(subject=TEST_BUCKET)
    out = sys.stdout.getvalue().strip()
    info = json.loads(out)[0]
    for k in ('bucket', 'info'):
        assert_in(k, info)
    bucket_info = info.get("info")
    for k in ('keys', 'size_human', 'size'):
        assert_in(k, bucket_info)
    key_info = bucket_info.get("keys")
    for k in ('count', 'largest', 'newest', 'oldest'):
        assert_in(k, key_info)


@mock_s3
def local_md5_test():
    # ensure original text
    with open(TEST_FILE, 'w') as test_file:
        test_file.write("data")
    radu = RadulaProxy(connection=boto.connect_s3())
    # 'threads' needed
    args = vars(_parse_args(["local-md5"]))
    args.update({
        "subject": TEST_FILE
    })
    radu.local_md5(**args)
    out = sys.stdout.getvalue().strip()
    assert_equal('8d777f385d3dfec8815d20f7496026dc', out)


@mock_s3
def local_md5_threads_test():
    # ensure original text
    with open(TEST_FILE, 'w') as test_file:
        test_file.write("data")
    radu = RadulaProxy(connection=boto.connect_s3())
    # 'threads' needed
    args = vars(_parse_args(["local-md5", "-t", "2"]))
    args.update({
        "subject": TEST_FILE
    })
    radu.local_md5(**args)
    out = sys.stdout.getvalue().strip()
    assert_equal('8d777f385d3dfec8815d20f7496026dc', out)


@mock_s3
@raises(RadulaError)
def local_md5_fail_test():
    radu = RadulaProxy(connection=boto.connect_s3())
    args = vars(_parse_args(["local-md5"]))
    args.update({
        "subject": 'test_file_not_found__intentional'
    })
    radu.local_md5(**args)


@mock_s3
@raises(RadulaError)
def local_md5_nosubject_test():
    radu = RadulaProxy(connection=boto.connect_s3())
    args = vars(_parse_args(["local-md5"]))
    radu.local_md5(**args)


@mock_s3
def remote_md5_test():
    # ensure original text
    with open(TEST_FILE, 'w') as test_file:
        test_file.write("data")
    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)

    # give something to download
    args = vars(_parse_args(['up']))
    args.update({
        "subject": TEST_FILE,
        "target": REMOTE_FILE
    })
    radu.upload(**args)
    sys.stdout.truncate(0)

    # 'threads' needed
    args = vars(_parse_args(["remote-md5", "-t", "2"]))
    args.update({
        "subject": REMOTE_FILE
    })
    radu.remote_md5(**args)
    out = sys.stdout.getvalue().strip()
    assert_equal('8d777f385d3dfec8815d20f7496026dc', out)


@mock_s3
@raises(RadulaError)
def remote_md5_fail_test():
    # ensure original text
    with open(TEST_FILE, 'w') as test_file:
        test_file.write("data")
    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)
    sys.stdout.truncate(0)

    # 'threads' needed
    args = vars(_parse_args(["remote-md5", "-t", "2"]))
    args.update({
        "subject": os.path.join(TEST_BUCKET,
                                'test_file_not_found__intentional')
    })
    radu.remote_md5(**args)


@mock_s3
@raises(RadulaError)
def remote_md5_nosubject_test():
    radu = RadulaProxy(connection=boto.connect_s3())
    args = vars(_parse_args(["remote-md5"]))
    radu.remote_md5(**args)


def verify_nosubject_test():
    test_sets = (
        {},
        {"subject": TEST_FILE},
        {"target": REMOTE_FILE}
    )
    for test_set in test_sets:
        yield verify_fail_method, test_set


@mock_s3
@raises(RadulaError)
def verify_fail_method(test_set):
    radu = RadulaProxy(connection=boto.connect_s3())
    args = vars(_parse_args(["verify"]))
    args.update(test_set)
    radu.verify(**args)


@mock_s3
def verify_test():
    # ensure original text
    with open(TEST_FILE, 'w') as test_file:
        test_file.write("data")
    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)

    # give something to download
    args = vars(_parse_args(['up']))
    args.update({
        "subject": TEST_FILE,
        "target": REMOTE_FILE
    })
    radu.upload(**args)
    sys.stdout.truncate(0)

    handler = TestHandler(Matcher())
    logger = logging.getLogger()
    logger.addHandler(handler)

    # 'threads' needed
    args = vars(_parse_args(["verify"]))
    args.update({
        "subject": TEST_FILE,
        "target": REMOTE_FILE
    })
    radu.verify(**args)

    assert_false(handler.matches(levelno=logging.ERROR))
    assert_false(handler.matches(levelno=logging.WARNING))
    assert_true(handler.matches(levelno=logging.INFO))
    msgs = [
        "Checksum Verified!",
        '8d777f385d3dfec8815d20f7496026dc',
    ]

    for msg in msgs:
        fmt = "Expecting log message containing '{0}'"
        assert_true(handler.matches(message=msg), msg=fmt.format(msg))


def copy_test():
    methods = ['sc', 'streaming-copy']
    for method in methods:
        yield copy_method, method


@mock_s3
def copy_method(method):
    handler = TestHandler(Matcher())
    logger = logging.getLogger()
    logger.addHandler(handler)
    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)

    # give something to copy
    args = vars(_parse_args(['up']))
    args.update({
        "subject": TEST_FILE,
        "target": REMOTE_FILE
    })
    radu.upload(**args)
    sys.stdout.truncate(0)

    # 'threads' needed
    args = vars(_parse_args(['-y', method]))
    target_file = REMOTE_FILE + '-copy'
    args.update({
        "subject": REMOTE_FILE,
        "target": target_file
    })
    radu.streaming_copy(**args)

    msgs = [
        "Finished uploading",
        TEST_BUCKET + ".s3.amazonaws.com/" + TEST_FILE_NAME,
        "Download URL",
        "Key data matches!"
    ]

    for msg in msgs:
        fmt = "Expecting log message containing '{0}'"
        assert_true(handler.matches(message=msg), msg=fmt.format(msg))

    radu.keys(subject=TEST_BUCKET)
    keys = [k.strip() for k in sys.stdout.getvalue().strip().split("\n")]
    expected = [REMOTE_FILE, target_file]

    fmt = "Expecting output containing '{0}'"
    for expected_key in expected:
        expected_key = os.path.basename(expected_key)
        assert_in(expected_key, keys, msg=fmt.format(expected_key))


@mock_s3
def recur_copy_test():
    handler = TestHandler(Matcher())
    logger = logging.getLogger()
    logger.addHandler(handler)
    radu = RadulaProxy(connection=boto.connect_s3())

    # give something to copy
    TEST_FILE_2 = TEST_FILE_NAME + '2'
    SRC_BUCKET = TEST_BUCKET
    DEST_BUCKET = TEST_BUCKET + '2'
    radu.make_bucket(subject=SRC_BUCKET)
    radu.make_bucket(subject=DEST_BUCKET)

    REMOTE_FILE = os.path.join(SRC_BUCKET, os.path.basename(TEST_FILE))
    REMOTE_FILE_2 = os.path.join(SRC_BUCKET, os.path.basename(TEST_FILE_2))

    for dest in [REMOTE_FILE, REMOTE_FILE_2]:
        args = vars(_parse_args(['up']))
        args.update({
            "subject": TEST_FILE,
            "target": dest
        })
        radu.upload(**args)
        sys.stdout.truncate(0)

    # 'threads' needed
    args = vars(_parse_args(['sc']))
    args.update({
        "subject": SRC_BUCKET + '/',
        "target": DEST_BUCKET + '/'
    })
    radu.streaming_copy(**args)

    msgs = [
        "Finished uploading",
        "Download URL: https://%s.s3.amazonaws.com/%s" % (DEST_BUCKET, TEST_FILE_NAME),
        "Download URL: https://%s.s3.amazonaws.com/%s" % (DEST_BUCKET, TEST_FILE_2),
    ]

    for msg in msgs:
        fmt = "Expecting log message containing '{0}'"
        assert_true(handler.matches(message=msg), msg=fmt.format(msg))

    radu.keys(subject=TEST_BUCKET)
    keys = [k.strip() for k in sys.stdout.getvalue().strip().split("\n")]
    expected = [REMOTE_FILE, REMOTE_FILE_2, TEST_FILE, TEST_FILE_2]

    fmt = "Expecting output containing '{0}'"
    for expected_key in expected:
        expected_key = os.path.basename(expected_key)
        assert_in(expected_key, keys, msg=fmt.format(expected_key))


@mock_s3
def __acl_test(opts, test_method):
    handler = TestHandler(Matcher())
    logger = logging.getLogger()
    logger.addHandler(handler)

    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)
    sys.stdout.truncate(0)

    test_set = {
        "subject": TEST_FILE,
        "target": REMOTE_FILE
    }

    args = vars(_parse_args(opts))
    args.update(test_set)
    getattr(radu, args.get("command"))(**args)

    msgs = [
        "SKIP ACL Sync"
    ]

    fmt = "Expecting log message containing '{0}'"
    for msg in msgs:
        test_method(
            handler.matches(message=msg),
            msg=fmt.format(msg)
        )


def url_test():
    methods = ['url', 'get_url']
    inputs = (
        (REMOTE_FILE, 10),
        (REMOTE_FILE, '60'),
        (REMOTE_FILE, None),
        (REMOTE_FILE + '*', 10),
        (REMOTE_FILE + '*', '60'),
        (REMOTE_FILE + '*', None),
    )
    for method in methods:
        for input in inputs:
            yield url_method, method, input


@mock_s3
def url_method(method, input):
    handler = TestHandler(Matcher())
    logger = logging.getLogger()
    logger.addHandler(handler)
    radu = RadulaProxy(connection=boto.connect_s3())
    radu.make_bucket(subject=TEST_BUCKET)

    # give something to copy
    args = vars(_parse_args(['up']))
    args.update({
        "subject": TEST_FILE,
        "target": REMOTE_FILE
    })
    radu.upload(**args)

    args.update({
        "subject": TEST_FILE,
        "target" : REMOTE_FILE + '2'
    })
    radu.upload(**args)
    sys.stdout.truncate(0)

    args.update({
        "subject": input[0],
        "target": input[1]
    })

    getattr(radu, method)(**args)

    fmt = "Expecting log message containing '{0}'"
    find = '?Signature='
    out = sys.stdout.getvalue().strip()
    assert_true(find in out, msg=fmt.format(find))


def skip_acl_test():
    __acl_test(["--no-acl", "up"], assert_true)


def no_skip_acl_test():
    __acl_test(["up"], assert_false)
