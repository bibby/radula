from argparse import ArgumentTypeError
from nose.tools import raises
from nose.tools import assert_equal
from radula import *
from radula.rad import human_size


def test_check_negative():
    for i in [0, 1, '1', 20, '100']:
        yield check_negative_pass, i


def check_negative_pass(i):
    assert_equal(int(i), check_negative(i))


def test_check_negative_fail():
    for i in [-1, '-2', -20]:
        yield check_negative_fail, i


@raises(ArgumentTypeError)
def check_negative_fail(n):
    check_negative(n)


def test_human_size():
    dataset = (
        (1, '1 B', 0),
        (2, '2 B', 0),
        (1024, '1 KB', 0),
        (1024, '1.00 KB', 2),
        (2048, '2 KB', 0),
        (1024 + 512, '1.50 KB', 2),
        (1024 * 1024, '1.0 MB', 1),
        (1024 * 1024 * 1024 * 2, '2.00 GB', None),
        (1024 * 1024 * 1024 * 2, '2 GB', 0),
        (1024 * 1024 * 1024 * 123456, '120.5625 TB', 4),
    )
    for i, o, p in dataset:
        yield comp_human_size, i, o, p


def comp_human_size(i, o, p):
    if p is None:
        assert_equal(o, human_size(i))
    else:
        assert_equal(o, human_size(i, precision=p))