import json
import os
import boto
from boto.exception import S3ResponseError
from moto import mock_s3
import sys
import logging
from radula import RadulaProxy, RadulaError, _parse_args, Radula
from nose.tools import assert_equal, assert_true, raises, assert_false, assert_in, assert_not_in
from log_match import TestHandler, Matcher

TEST_BUCKET = "tests"
TEST_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data.txt")
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
                "threads": Radula.DEFAULT_UPLOAD_THREADS,
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
    assert_equal('Created bucket: tests', out)


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
        "tests.s3.amazonaws.com/data.txt",
        "Checksum Verified!"
    ]

    for msg in msgs:
        assert_true(handler.matches(message=msg), msg="Expecting log message containing '{0}'".format(msg))


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
    methods = ["dl", "get", "download"]
    test_sets = [
        {"subject": REMOTE_FILE,
         "target": TEST_FILE + "2"},
        {"subject": REMOTE_FILE}
    ]

    for method in methods:
        for test_set in test_sets:
            yield dl_method, method, test_set


@mock_s3
def dl_method(method, test_set):
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
        assert_in(msg, out, msg="Expecting log message containing '{0}'".format(msg))
    target = test_set.get("target", TEST_FILE)
    assert_true(os.path.isfile(target))
    if target != TEST_FILE:
        os.remove(target)


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
        assert_in(expected_key, keys, msg="Expecting output containing '{0}'".format(expected_key))


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
        assert_in(absent_key, keys, msg="Expecting output containing '{0}'".format(absent_key))
        sys.stdout.truncate(0)

        radu.keys(subject=TEST_BUCKET)
        keys = [k.strip() for k in sys.stdout.getvalue().strip().split("\n")]

        assert_not_in(absent_key, keys, msg="Expecting absence of key mention '{0}'".format(absent_key))
        for expected_key in expected:
            expected_key = os.path.basename(expected_key)
            assert_in(expected_key, keys, msg="Expecting output containing '{0}'".format(expected_key))


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
def local_md5_threads_test():
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
        "subject": os.path.join(TEST_BUCKET, 'test_file_not_found__intentional')
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
        assert_true(handler.matches(message=msg), msg="Expecting log message containing '{0}'".format(msg))


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

    # give something to download
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
        "tests.s3.amazonaws.com/data.txt",
        "Download URL",
        "Checksum Verified!"
    ]

    for msg in msgs:
        assert_true(handler.matches(message=msg), msg="Expecting log message containing '{0}'".format(msg))

    radu.keys(subject=TEST_BUCKET)
    keys = [k.strip() for k in sys.stdout.getvalue().strip().split("\n")]
    expected = [REMOTE_FILE, target_file]

    for expected_key in expected:
        expected_key = os.path.basename(expected_key)
        assert_in(expected_key, keys, msg="Expecting output containing '{0}'".format(expected_key))