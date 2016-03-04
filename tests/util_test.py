import inspect
from argparse import ArgumentTypeError
from nose.tools import raises, assert_equal
from radula.rad import Radula, RadulaLib, _gib, _gb, _mib, _mb, \
    human_size, from_human_size, calculate_chunks, legacy_calculate_chunks, \
    guess_target_name
from radula import check_negative

_tib = _gib * 1024


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
        (1000, '1 KB', 0),
        (1000, '1.00 KB', 2),
        (2000, '2 KB', 0),
        (1000 + 500, '1.50 KB', 2),
        (1000 * 1000, '1.0 MB', 1),
        (1000 * 1000 * 1000 * 2, '2.00 GB', None),
        (1000 * 1000 * 1000 * 2, '2 GB', 0),
        (1000 * 1000 * 1000 * 123456, '123.4560 TB', 4),
    )
    for i, o, p in dataset:
        yield comp_human_size, i, o, p


def comp_human_size(i, o, p):
    if p is None:
        assert_equal(o, human_size(i))
    else:
        assert_equal(o, human_size(i, precision=p))


def test_from_human_size():
    dataset = (
        # in, out
        (1, 1),
        ('1', 1),
        (u'1', 1),
        (_mb, 1000 * 1000),
        (_mib, 1024 * 1024),
        (_gb, 1000 * 1000 * 1000),
        (_gib, 1024 * 1024 * 1024),
        (RadulaLib.MIN_CHUNK - 1, RadulaLib.MIN_CHUNK - 1),
        (RadulaLib.MIN_CHUNK + 0, RadulaLib.MIN_CHUNK),
        (RadulaLib.MIN_CHUNK + 1, RadulaLib.MIN_CHUNK + 1),
        ('1B', 1),
        ('2B', 2),
        ('1K', 1000),
        ('2kib', 1024 * 2),
        ('3mb', _mb * 3),
        ('7mib', _mib * 7),
        ('111m', _mb * 111),
        ('6g', _gb * 6),
        ('777tib', _tib * 777)
    )

    for _in, _out in dataset:
        yield comp_from_human_size, _in, _out, 0, 0

    dataset = (
        # in, out
        (1, 0),
        ('1', 0),
        (u'1', 0),
        (RadulaLib.MIN_CHUNK - 1, 0),
        (RadulaLib.MIN_CHUNK + 0, RadulaLib.MIN_CHUNK),
        (RadulaLib.MIN_CHUNK + 1, RadulaLib.MIN_CHUNK + 1),
        ('1g', _gb * 1),
        ('2g', _gb * 2),
    )

    for _in, _out in dataset:
        yield comp_from_human_size, _in, _out, RadulaLib.MIN_CHUNK, 0

    dataset = (
        # in, out
        (RadulaLib.MIN_CHUNK - 10, 999, 999),
        (RadulaLib.MIN_CHUNK - 1, 888, 888),
        (RadulaLib.MIN_CHUNK, RadulaLib.MIN_CHUNK, 777),
        (RadulaLib.MIN_CHUNK + 1, RadulaLib.MIN_CHUNK + 1, 666),
    )

    for _in, _out, default in dataset:
        yield comp_from_human_size, _in, _out, RadulaLib.MIN_CHUNK, default


def comp_from_human_size(_in, expected, minimum, default):
    assert_equal(expected, from_human_size(str(_in), minimum=minimum, default=default))


def guess_target_name_test():
    test_sets = (
        # source, target, expected
        ("src", "", "src"),
        ("src", "path/", "path/src"),
        ("src", "path/src2", "path/src2"),
        ("src", "path", "path"),
        ("path/to/src", "", "src"),
        ("path/to/src", "path/", "path/src"),
    )
    for subject, target, expected in test_sets:
        yield guess_method, subject, target, expected


def guess_method(subject, target, expected):
    assert_equal(expected, guess_target_name(subject, target))


def lineno():
    """Returns the current line number in our program."""
    return inspect.currentframe().f_back.f_lineno


def test_chunk_size():
    dataset = (
        # line  size    count   chunk
        (lineno(), 1 * _mib, 1, 1 * _mib),
        (lineno(), 2 * _mib, 1, 2 * _mib),
        (lineno(), 32 * _mib, 1, 32 * _mib),
        (lineno(), 64 * _mib, 1, 64 * _mib),
        (lineno(), 128 * _mib, 2, Radula.DEFAULT_CHUNK),
        (lineno(), 256 * _mib, 3, Radula.DEFAULT_CHUNK),
        (lineno(), 512 * _mib, 6, Radula.DEFAULT_CHUNK),
        (lineno(), 1024 * _mib, 11, Radula.DEFAULT_CHUNK),
        (lineno(), 1 * _gib, 11, Radula.DEFAULT_CHUNK),
        (lineno(), 2 * _gib, 22, Radula.DEFAULT_CHUNK),
        (lineno(), 4 * _gib, 43, Radula.DEFAULT_CHUNK),

        (lineno(), 5000 * _mb - 1, 50, Radula.DEFAULT_CHUNK),
        (lineno(), 5000 * _mb + 0, 50, Radula.DEFAULT_CHUNK),
        (lineno(), 5000 * _mb + 1, 51, Radula.DEFAULT_CHUNK),
        (lineno(), 5001 * _mb, 51, Radula.DEFAULT_CHUNK),

        (lineno(), 50000 * _mb - 1, 500, Radula.DEFAULT_CHUNK),
        (lineno(), 50000 * _mb + 0, 500, Radula.DEFAULT_CHUNK),
        (lineno(), 50000 * _mb + 1, 501, Radula.DEFAULT_CHUNK),

        (lineno(), 50 * _gb - _mb, 500, Radula.DEFAULT_CHUNK),
        (lineno(), 50 * _gb + 0, 500, Radula.DEFAULT_CHUNK),
        (lineno(), 50 * _gb + _mb, 501, Radula.DEFAULT_CHUNK),

        (lineno(), 64 * _gb, 640, 1 * Radula.DEFAULT_CHUNK),
        (lineno(), 128 * _gb, 1280, 1 * Radula.DEFAULT_CHUNK),
        (lineno(), 256 * _gb, 2560, 1 * Radula.DEFAULT_CHUNK),
        (lineno(), 512 * _gb, 5120, 1 * Radula.DEFAULT_CHUNK),
        (lineno(), 1024 * _gb, 10240, 1 * Radula.DEFAULT_CHUNK),
    )

    for id, size, num, chunk in dataset:
        yield comp_chunk_size, id, size, num, chunk


def comp_chunk_size(lineno, size, num, chunk):
    def m(label, expected, actual):
        msg = "line {0}: Given size {1} ({2}), expected {3} of {4}; received {5}"
        return msg.format(lineno, size, human_size(size), label, expected, actual)

    actual_num, actual_chunk = calculate_chunks(size)
    assert_equal(num, actual_num, m("chunk count", num, actual_num))
    assert_equal(chunk, actual_chunk, m("chunk size", chunk, actual_chunk))


def test_legacy_chunk_size():
    dataset = (
        # line  size    count   chunk
        (lineno(), 1 * _mib, 1, 1 * _mib),
        (lineno(), 2 * _mib, 1, 2 * _mib),
        (lineno(), 32 * _mib, 1, 32 * _mib),
        (lineno(), 64 * _mib, 1, 64 * _mib),
        (lineno(), 128 * _mib, 2, 100 * _mib),
        (lineno(), 256 * _mib, 3, 100 * _mib),
        (lineno(), 512 * _mib, 6, 100 * _mib),
        (lineno(), 1024 * _mib, 11, 100 * _mib),
        (lineno(), 1 * _gib, 11, 100 * _mib),
        (lineno(), 2 * _gib, 21, 100 * _mib),
        (lineno(), 4 * _gib, 41, 100 * _mib),

        (lineno(), 5000 * _mib - 1, 50, 100 * _mib),
        (lineno(), 5000 * _mib + 0, 50, 100 * _mib),
        (lineno(), 5000 * _mib + 1, 50, 100 * _mib + 1),
        (lineno(), 5001 * _mib, 50, 100 * _mib + 20972),

        (lineno(), 50000 * _mib - 1, 50, 1000 * _mib),
        (lineno(), 50000 * _mib + 0, 50, 1000 * _mib),
        (lineno(), 50000 * _mib + 1, 50, 1000 * _mib + 1),

        (lineno(), 50 * _gib - _mib, 50, 1 * _gib - 20971),
        (lineno(), 50 * _gib + 0, 50, 1 * _gib),
        (lineno(), 50 * _gib + _mib, 51, 1 * _gib),

        (lineno(), 64 * _gib, 64, 1 * _gib),
        (lineno(), 128 * _gib, 128, 1 * _gib),
        (lineno(), 256 * _gib, 256, 1 * _gib),
        (lineno(), 512 * _gib, 512, 1 * _gib),
        (lineno(), 1024 * _gib, 1024, 1 * _gib),
    )

    for id, size, num, chunk in dataset:
        yield comp_legacy_chunk_size, id, size, num, chunk


def comp_legacy_chunk_size(lineno, size, num, chunk):
    def m(label, expected, actual):
        msg = "line {0}: Given size {1} ({2}), expected {3} of {4}; received {5}"
        return msg.format(lineno, size, human_size(size), label, expected, actual)

    actual_num, actual_chunk = legacy_calculate_chunks(size)
    assert_equal(num, actual_num, m("chunk count", num, actual_num))
    assert_equal(chunk, actual_chunk, m("chunk size", chunk, actual_chunk))
