radula
======

radula is a small utility to add some friendliness to
`RadosGW <http://ceph.com/docs/master/man/8/radosgw/>`__ for our team
working with `Ceph <http://ceph.com/>`__ for S3-like storage. Little
more than a wrapper for
`boto <http://boto.readthedocs.org/en/latest/>`__ radula saves us time
and headache by using nice defaults.

The primary functions for the current version are

-  Inspect radosgw bucket/key ACLs
-  Spot differences between bucket and key ACLs
-  Allow or disallow user read/write to buckets and keys
-  When modifying a bucket ACL, modify the ACLs for keys as well
-  Verify uploads using checksums
-  Upload using multiple threads

The name, "radula", is a `cephalopod-related
term <https://en.wikipedia.org/wiki/Radula#In_cephalopods>`__ that hit
close to RADOS. It's not a tongue, or really even teeth; it's more like
if your tongue had teeth. Spooky.

Installation
------------

Install radula from `pypi <https://pypi.python.org/pypi>`__ using
``pip``.

::

    pip install radula

The ``radula`` command should be available in your ``$PATH``.

Testing
-------

Install the pip packages listed in ``testing-requirements.txt`` and run ``nosetests``.

::

    $ pip install -U -r testing-requirements.txt
    $ nosetests --with-coverage --cover-package=radula

The effort to increase code coverage is ongoing.



Configure
---------

radula uses *boto*, so all configuration is really `boto
configuration <http://boto.readthedocs.org/en/latest/s3_tut.html>`__.
Notable changes are replacing the url to amazon aws with that of one of
your gateways. Where applicable, you may have to disable SSL as a
default option.

::

    # example shared /etc/boto.cfg
    [s3]
    host = radosgw1.your_company.com

    [Boto]
    is_secure = False

To add your personal credentials, fill in the following in ``~/.boto``:

::

    [Credentials]
    aws_access_key_id = abcdef...
    aws_secret_access_key = 0123456...

    [profile other_role]
    aws_access_key_id = wxyz...
    aws_secret_access_key = 9765432...

Usage
-----

The command structure for radula is
``radula [flags] command subject [target]``. The "subject" matter or
"target" of a request could be a local resource or a remote one,
depending on the command being executed. These could be read as "source"
and "destination" in some cases, but the intent is simply to flow left
to right.

::

    $ radula -h
    usage: radula [-h] [--version] [-r] [-w] [-t THREADS] [-p PROFILE]
           [-d DESTINATION] [-f] [-y] [-c CHUNK_SIZE] [-l] [-n] [-z]
           [{get-acl,set-acl,compare-acl,sync-acl,allow,allow-user,disallow,disallow-user,mb,make-bucket,
           rb,remove-bucket,lb,list-buckets,put,up,upload,get,dl,download,mpl,mp-list,multipart-list,
           mpc,mp-clean,multipart-clean,rm,remove,keys,info,size,etag,local-md5,remote-md5,verify,
           sc,streaming-copy,cat}]
           [subject] [target] ...

    RadosGW client

    positional arguments:
      {
        get-acl,set-acl,compare-acl,sync-acl,
        allow,allow-user,disallow,disallow-user,
        mb,make-bucket,
        rb,remove-bucket,
        lb,list-buckets,
        put,up,upload,
        get,dl,download,
        mpl,mp-list,multipart-list,
        mpc,mp-clean,multipart-clean,
        rm,remove,
        keys,info,size,etag,
        local-md5,remote-md5,
        verify,
        sc,streaming-copy,cat
      } command
      subject               Subject
      target                Target
      remainder             Additional targets for supporting commands. See README

      optional arguments:
        -h, --help            show this help message and exit
        --version             Prints version number
        -r, --read            During a user grant, permission includes reads
        -w, --write           During a user grant, permission includes writes
        -t THREADS, --threads THREADS
                              Number of threads to use for uploads. Default=10
        -p PROFILE, --profile PROFILE
                              Boto profile. Overrides AWS_PROFILE environment var
        -d DESTINATION, --destination DESTINATION
                              Destination boto profile, required for streaming copy
        -f, --force           Overwrite local files without confirmation
        -y, --verify          Verify uploads after they complete. Uses --threads
        -c CHUNK_SIZE, --chunk CHUNK_SIZE
                              multipart upload chunk size in bytes.
        -l, --long-keys       prepends bucketname to key results.
        -n, --dry-run         Print would-be deletions without deleting
        -z, --resume          Resume uploads if needed.


Examples
--------

This is a quick walkthrough of the features so far. In these scenarios,
we acting as the user ``bibby``, who owns the rados bucket ``mybucket``.
In some of the examples, we'll be manipulating the access to this bucket
for a second user called ``fred``.

Contained in the bucket are two regular files: ``hello`` and ``world``.

Displaying bucket ACL
~~~~~~~~~~~~~~~~~~~~~

::

    [bibby@machine ~]$ radula get-acl mybucket
    ACL for bucket: mybucket
    [CanonicalUser:OWNER] Andrew Bibby = FULL_CONTROL

The command ``get-acl`` prints the acl. radula assumed that the term
``mybucket`` was a bucket, being that it was a lone term.

Displaying key ACL
~~~~~~~~~~~~~~~~~~

::

    [bibby@machine ~]$ radula get-acl mybucket/hello
    ACL for key: mybucket/hello
    [CanonicalUser:OWNER] Andrew Bibby = FULL_CONTROL

Because the term contained a slash, the subject is correctly identified
as ``hello`` within the bucket ``mybucket``.

Comparing ACLs - Keys in bucket
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    [bibby@machine ~]$ radula compare-acl mybucket
    Bucket ACL for: mybucket
    [CanonicalUser:OWNER] Andrew Bibby = FULL_CONTROL
    ---------

    Keys with identical ACL: 2
    Keys with different ACL: 0

The ``compare-acl`` command on a bucket will report of the *sameness* of
ACLs across the keys as compared to the bucket. We'll see this again
later in another example.

This *can* be run against one key, limiting the compared objects to the
one key against its bucket

::

    [bibby@machine ~]$ radula check-acl mybucket/hello
    Bucket ACL for: mybucket
    [CanonicalUser:OWNER] Andrew Bibby = FULL_CONTROL
    ---------

    Keys with identical ACL: 1
    Keys with different ACL: 0

Set a canned ACL
~~~~~~~~~~~~~~~~

Can set the ACL of a bucket or key to one of the four AWS "canned"
policies using ``set-acl``. In this scenario, the *subject* can be a
bucket or a key, with the *target* being a canned policy name.

::

    [bibby@machine ~]$ radula set-acl mybucket/hello public-read
    << prints the output of get-acl after completing the operation

Changing the ACL on a bucket **will** will be applied to the keys as
well, potentially overwriting any custom access given to keys. Run
``compare-acl`` before setting the bucket ACL to discover any special
differences, as they may need to be recreated after the ``set-acl``
operation completes.

Sync ACLs
~~~~~~~~~

Should a difference of ACL had appeared, we could forcefully replace all
key ACLs with the bucket's ACL using ``sync-acl``.

::

    [bibby@machine ~]$ radula sync-acl mybucket
    Bucket ACL for: mybucket
    [CanonicalUser:OWNER] Andrew Bibby = FULL_CONTROL
    ---------

    Setting bucket's ACL on hello
    Setting bucket's ACL on world

This is a ``PUT`` command, so it doesn't bother to look at the current
ACL for the keys; it just puts a copy of the bucket's own ACL.

``sync-acl`` can be done on a single key as well.

::

    [bibby@machine ~]$ radula sync-acl mybucket/world
    Setting bucket's ACL on world

Granting access to a key
~~~~~~~~~~~~~~~~~~~~~~~~

To grant access to another user, we'll make use of some new flags.
``-r`` and/or ``-w`` to indicate read and write. A grant may have one or
both of ``rw``. If both are absent, ``read`` is assumed. Permissions are
separate, so it is possible to have a *write-only* grant.

For permission grants the *subject* is the **user** (as far as the usage
format in the help text goes), and the *target* is the **key or
bucket**.

::

    [bibby@machine ~]$ radula allow fred mybucket/hello
    granting READ to fred on key hello

Multiple grants to the same user for the same permission are possible in
rados and on s3, but radula will guard against that and ignore the
duplicate entry. Here, we'll add "read-write":

::

    [bibby@machine ~]$ radula -wr allow fred mybucket/hello
    User fred already has READ for key hello, skipping
    granting WRITE to fred on key hello

Granting access to a bucket
~~~~~~~~~~~~~~~~~~~~~~~~~~~

| Granting access to a bucket works the same way.
| When a bucket ACL is modified, **so are all of its keys**. That action is really the whole purpose behind radula.

::

    [bibby@machine ~]$ radula -wr allow fred mybucket
    granting READ to fred on bucket mybucket
    granting WRITE to fred on bucket mybucket
    User fred already has READ for key <Key: mybucket,hello>, skipping
    User fred already has WRITE for key <Key: mybucket,hello>, skipping
    granting READ to fred on key <Key: mybucket,world>
    granting WRITE to fred on key <Key: mybucket,world>

With both ``allow`` and ``disallow``, if an ACL difference exists
between the bucket and a key, that difference may still exist after the
modification. With these commands, we aren't **syncing** a modified
bucket ACL down to the keys; we're applying the same singular change to
each target individually.

Disallow (buckets and keys)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Removing permissions works similarly to granting access, but with some
differences. One assumption is about the omission of the read-write
flags; If neither are present, both permissions are removed.

+---------+---------+----------+
| start   | flags   | result   |
+=========+=========+==========+
| RW      | -r      | W        |
+---------+---------+----------+
| RW      | -w      | R        |
+---------+---------+----------+
| RW      | -rw     | -        |
+---------+---------+----------+
| RW      | -       | -        |
+---------+---------+----------+

ACLs for the keys are modified first. The user's access cannot be taken
away from the bucket if it still exists for one of its keys, so the
changes take place from bottom up.

Creating an difference and syncing down
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Starting with a blank slate:

::

    [bibby@machine ~]$ radula -wr disallow fred mybucket
    No change for <Key: mybucket,hello>
    No change for <Key: mybucket,world>
    No change for mybucket

Give ``fred`` read on the bucket

::

    [bibby@machine ~]$ radula -r allow fred mybucket
    granting READ to fred on bucket mybucket
    granting READ to fred on key <Key: mybucket,hello>
    granting READ to fred on key <Key: mybucket,world>

Give ``fred`` write on one key

::

    [bibby@machine ~]$ radula -w allow fred mybucket/world
    granting WRITE to fred on key world

Confirm the difference..

::

    [bibby@machine ~]$ radula compare-acl mybucket
    Bucket ACL for: mybucket
    [CanonicalUser:OWNER] Andrew Bibby = FULL_CONTROL
    [CanonicalUser] Fred Fredricks = READ
    ---------

    Difference in world:
    [CanonicalUser:OWNER] Andrew Bibby = FULL_CONTROL
    [CanonicalUser] Fred Fredricks = READ
    [CanonicalUser] Fred Fredricks = WRITE

    Keys with identical ACL: 1
    Keys with different ACL: 1

Plow the keys with the bucket's settings.

::

    [bibby@machine ~]$ radula sync-acl mybucket
    Bucket ACL for: mybucket
    [CanonicalUser:OWNER] Andrew Bibby = FULL_CONTROL
    [CanonicalUser] Fred Fredricks = READ
    ---------

    Setting bucket's ACL on hello
    Setting bucket's ACL on world

    [bibby@machine ~]$ radula check-acl mybucket
    Bucket ACL for: mybucket
    [CanonicalUser:OWNER] Andrew Bibby = FULL_CONTROL
    [CanonicalUser] Fred Fredricks = READ
    ---------

    Keys with identical ACL: 2
    Keys with different ACL: 0

Upload and Download
-------------------

These functions are similar for moving files in and out of the radosgw.
Its intention is not to replace better tools like ``s3cmd``, but rather
to cover some very common use cases so that the installation and
configuration of additional libraries *might* not be needed.

put, up, upload
~~~~~~~~~~~~~~~

The commands ``put``, ``up``, and ``upload`` are equivalent. For these
examples, I've chosen to use ``up``.

The syntax is ``radula up {source} {target}``, where *source* is a local
file or a glob. The *target* is a in radosgw path, and its behavior
depends on the singularity or plurality of the source given.

If the target path ends with a slash (``/``), then the key is presumed
to be the basename of the object appended at that path. *See table
below.*

If multiple source files are given, the key will always assume it is
part of a path, making an ending slash wholly optional.

When using globs, it's important to know that the argument must be
quoted to avoid shell expansion. For example to upload all files
starting with the letter ``a`` from ``path``, the command would be

::

    radula up 'path/a*' bucket/path

+--------------+-----------------+-----------------------------------------+
| source       | target          | result                                  |
+==============+=================+=========================================+
| /some/file   | bucket          | bucket/file                             |
+--------------+-----------------+-----------------------------------------+
| /some/file   | bucket/file     | bucket/file                             |
+--------------+-----------------+-----------------------------------------+
| /some/file   | bucket/named    | bucket/named                            |
+--------------+-----------------+-----------------------------------------+
| /some/file   | bucket/named/   | bucket/named/file                       |
+--------------+-----------------+-----------------------------------------+
| /some/f\*    | bucket/named    | bucket/named/file, bucket/named/file2   |
+--------------+-----------------+-----------------------------------------+
| /some/f\*    | bucket/named/   | bucket/named/file, bucket/named/file2   |
+--------------+-----------------+-----------------------------------------+

For faster multipart uploads, the default number of threads used is
``10``, but this can be set during upload using the ``-t`` option.

::

    # upload a large file using 16 threads
    radula -t 16 up large_file bucket

Upload verification via checksum can be enabled by adding the ``-y``,
``--verify`` flag.

As of ``radula v0.6.6``, uploads to a remote key that already exists
will abort if `-f, --force` is not also given. The reason is to guard
against accidentally loss of data in ceph.

Should portions of a multipart upload fail, there is a chance that it
can be resumed. A reattempt at upload should abort citing the presence
of a lingering multipart upload in progress. The `multipart-list` command
should confirm as much. Adding the ``-z,--resume`` flag to the original
upload command will inspect the uploaded parts and upload those that are absent
or differ in checksum. The resume will be slower for each part, as the local
parts are hashed and compared to the uploaded parts. Adding a verification step
with ``-y,--verify`` is recommended.

::

    # an upload resumation with verification
    radula -t 16 -zy up large_file bucket


get, dl, download
~~~~~~~~~~~~~~~~~

The commands ``get``, ``dl``, and ``downlaod`` are equivalent. For these
examples, I've chosen to use ``dl``.

The the syntax is ``radula dl {source} [{target}]``. The *target* is
optional, and will default to the basename of the remote file to be
stored in the current working directory.

Unlike ``up``, the download commands do not support globs.

+--------------------+--------------+----------------+
| source             | target       | result         |
+====================+==============+================+
| bucket/path/file   |              | ./file         |
+--------------------+--------------+----------------+
| bucket/path/file   | some\_file   | ./some\_file   |
+--------------------+--------------+----------------+
| bucket/path/file   | dir          | dir/file       |
+--------------------+--------------+----------------+
| bucket/path/file   | dir/named    | dir/named      |
+--------------------+--------------+----------------+

No attempt is made to create local paths that do not exist prior to
download; in the table above ``dir`` is an existing directory.

If a file with the target name already exists, ``radula`` will ask if
you wish to overwrite it unless the ``-f, --force`` flag is enabled.

As of ``radula v0.6.6``, downloads are multi-threaded using 10 processes by default,
which can be controlled with the ``-t, --threads`` flag.
This is known to have issues writing to glusterfs, so `-t 1` is recommended in that instance.

cat
~~~

An alternative to `download` is `cat`, which prints the contents of a remote subject
to `stdout`.

::

    $ echo "Hello there you" > hello
    $ radula up hello mybucket/hello
    INFO:radula:Finished uploading 16.00 B in 0.08s (188.82 Bps)
    $ radula cat mybucket/hello
    Hello there you

In radula 0.7+, `cat` accept the `-c`,`--chunk-size` parameter to print part of the remote file.
Unique to this command is that the chunk param can be a range of integers or humanized units.
If humanized units (ie, `2kb`) are used, they'll be converted into integer to conform with the
[HTTP Range header spec](https://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.35).

When using a range query, the end of the range may be omitted to include everything from
the starting position to the end of the file.

Omitting the first argument is not supported. Starting a range with zero (`0-n`) *does work*, but it is recommended to simply provide `n` by itself, because the **range in inclusive**. The range `0-100` would
output 101 bytes, while input `100` returns 100.

A `ValueError` will be raised if end of the range is before the starting position.

::

    # first two bytes
    $ radula -c 2 cat mybucket/hello
    he

    # 2 bytes in until the end
    $ radula -c '2-' cat mybucket/hello
    llo

    # first byte to second byte (inclusive)
    $ radula -c '1-2' cat mybucket/hello
    el

verify uploads
~~~~~~~~~~~~~~

Checksums can be obtained using ``local-md5`` and ``remote-md5``, and
easily compared with ``verify``.

The ``local-md5`` command expects one local file argument, and will
generate the same hash that is expected to be found on the remote.
Multipart upload size matters, so the output hash may differ if uploaded
by another mechanism.

The ``remote-md5`` command expects one remote file uri, ie
*mybucket/path/myfile*. It will return the ``etag`` attribute associated
with the key, which will typically be a file md5 or conglomeration of
multipart upload hashs with a number tacked at the end.

Calling ``verify [local_file] [remote_file]`` simply runs the operations
mentioned above and tests their outputs for likeness.

To view raw metadata about a remote target, use ``info [remote_file]``.
The output will contain the etag and other data in JSON format.
For quick access to size and hash data, commands ``etag`` and ``size``
are available to provide this data from the larger ``info`` set.

deletion
~~~~~~~~

Remote objects can be deleted using the commands `rm` or `remove`. While the majority of `radula` commands follow the position pattern of `subject, target`, the deletion command operates exclusively on remote objects. Therefore, it is one of the few that accept an arbitrary number of arguments. Globs are supported **if** they are quoted so as not to expand in the shell.

Use the `-n`,`--dry-run` flag to preview deletions without making any changes.

::

    [bibby@machine ~]$ radula --dry-run rm mybucket/x
    DRY-RUN: rm mybucket/x

    [bibby@machine ~]$ radula rm mybucket/x 'mybucket/y*'
    x
    y1
    y2


Cleaning up messes
------------------

If multipart uploads go awry, they can leave behind some unfinished
artifacts in the form of orphaned upload parts. ``radula`` can now list
these can clean up.

The commands ``multipart-list``, ``mp-list``, and ``mpl`` are
equivalent. For these examples, I've chosen to use ``mp-list``.

Listing can be done by bucket or for a key:

::

    # list multipart uploads for a bucket
    $ radula mp-list mybucket
    bibby    ones.img        2~Q8r-pWTmMTbx_rhHa8-u3I3m-vjCF5F       Andrew Bibby    2015-09-23T19:39:14.000Z
    bibby    zeros.img       2~MvM7KTr2sMcS_SfVzWO7T0chzJRUqvm       Andrew Bibby    2015-09-23T19:35:44.000Z

    # list multipart uploads for a key
    $ radula mp-list mybucket/zeros.img
    bibby    zeros.img       2~MvM7KTr2sMcS_SfVzWO7T0chzJRUqvm       Andrew Bibby    2015-09-23T19:35:44.000Z

Cleaning up a failed multi-part upload is as easy using a *clean*
command in place of *list*.

The commands ``multipart-clean``, ``mp-clean``, and ``mpc`` are
equivalent. For these examples, I've chosen to use ``mp-clean``.

::

    # clean multipart uploads for a key
    $ radula mp-clean mybucket/zeros.img
    INFO:root:Canceling zeros.img 2~MvM7KTr2sMcS_SfVzWO7T0chzJRUqvm
    True

    # clean multipart uploads for a bucket
    $ radula mp-list mybucket
    INFO:root:Canceling ones.img 2~Q8r-pWTmMTbx_rhHa8-u3I3m-vjCF5F
    True

Streaming Copy
--------------

Since radula 0.5.0, users are able to copy between different ceph
installations, or different buckets within the same installation,
without copying to the local disk. To facilitate this in the friendliest
possible manner, we've extended the ``boto`` configuration slightly to
be able to specify a separate s3 host for a particular profile.

The ``profile`` sections of ``~/.boto`` or ``/etc/boto.cfg`` can now
accept the following items that are not supported by regular boto:

-  host (string)
-  port (int)
-  is\_secure (bool)

An example extended profile

::

    [profile second_ceph]
    aws_access_key_id = wxyz...
    aws_secret_access_key = 9765432...
    host = second.ceph.of.mine
    port = 8184

The commans ``streaming-copy`` and ``sc`` are equivalent. For these
example, I've chosen to use ``sc``.

When copying, the ``-p`` flag will apply the aws\_profile for the
*source*/subject. Omitting this flag will use the default boto
credentials for the source.

The ``-d`` flag will specify the profile used for the
*destination*/target to receive the files. Naming ``-d Default`` will
use the default boto credentials for the destination.

Copy a file from first-ceph to second-ceph
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``radula sc -d second mybucket/file other_bucket/file``

The above command used the default boto profile to send ``file`` from
``mybucket`` located on the default ceph to the ceph defined in the
profile named ``second``.

Copy a file from second-ceph to first-ceph
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``radula -p second -d Default other_bucket/file mybucket/file``

This is the inverse of the previous example. Using the ``second``
profile as the source/subject (as specified by ``-p second``), we're
transfering a file to ``mybucket/file`` located on the default s3 using
the default profile (as specified by ``-d Default``).

Copy profile to profile
~~~~~~~~~~~~~~~~~~~~~~~

Avoiding the use of default profiles all together, you can copy using
both ``-p`` and ``-d`` flags.

``radula -p here -d there here/stuff there/stuff``
