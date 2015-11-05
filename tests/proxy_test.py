import os
import boto
from moto import mock_s3
import sys
import logging
from radula import RadulaProxy, RadulaError, _parse_args
from nose.tools import assert_equal, assert_true, raises, assert_false, assert_in
from log_match import TestHandler, Matcher

TEST_BUCKET = "tests"
TEST_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data.txt")
REMOTE_FILE = os.path.join(TEST_BUCKET, os.path.basename(TEST_FILE))


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

    args = vars(_parse_args([method]))
    args.update(test_set)
    getattr(radu, method)(**args)

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

    args = vars(_parse_args([method, '-f']))
    args.update(test_set)
    getattr(radu, method)(**args)

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
    out = sys.stdout.getvalue().strip()

    for msg in expected:
        assert_in(msg[len(TEST_BUCKET) + 1:], out, msg="Expecting log message containing '{0}'".format(msg))