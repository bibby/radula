from ._version import get_versions
from datetime import datetime
import os
import sys
import fnmatch
import time
import logging
import binascii
from hashlib import md5
from glob import glob
import boto
from boto.exception import S3ResponseError
from parallel import ParallelSim
import boto.s3.connection
from boto.s3.bucket import Bucket
from boto.s3.key import Key
from math import ceil
from cStringIO import StringIO
import re

logger = logging.getLogger("radula")

__version__ = get_versions()['version']
RadulaHeaders = {
    'version': 'radula-version',
    'parts': 'radula-num-parts',
    'chunk_size': 'radula-chunk-size',
}

_mb = 1000 * 1000
_gb = _mb * 1000
_mib = 1024 * 1024
_gib = _mib * 1024


class RadulaError(Exception):
    pass


class RadulaChunkStrategy:
    DEFAULT = 0
    LEGACY = 1


class RadulaACLChange:
    DISALLOW = 0
    ALLOW = 1


class RadulaClient(object):
    DEFAULT_THREADS = 3
    MIN_CHUNK = _mb * 10
    DEFAULT_CHUNK = _mb * 100

    def __init__(self, connection=None):
        self.conn = connection
        self.profile = None
        self.encrypt_keys = None
        self.thread_count = RadulaClient.DEFAULT_THREADS
        self.chunk_size = Radula.DEFAULT_CHUNK
        self._is_secure_placeholder = None

    def connect(self, profile=None, connection=None):
        """create or reuse a boto s3 connection.
        An option aws profile may be given.
        """
        if profile:
            self.profile = profile

        if boto.config.getint('Boto', 'debug', 0) > 0:
            boto.set_stream_logger('boto')

        if connection:
            self.conn = connection

        if not self.conn:
            self.conn = self.new_connection(profile)
        return self.conn

    def new_connection(self, profile=None, **kwargs):
        """create a fresh boto s3 connection"""
        args = {}

        if profile:
            """ when directed to use a profile, check if it
            stipulate host, port, and/or is_secure and manually
            add those to the args """
            args['profile_name'] = profile
            profile_name = 'profile {name}'.format(name=profile)
            if boto.config.has_section(profile_name):
                logger.debug("profile %s exists", profile_name)
                port = boto.config.get(profile_name, 'port', None)
                if port:
                    logger.debug("profile %s uses port %d",
                                 profile_name, int(port))
                    args['port'] = int(port)
                host = boto.config.get(profile_name, 'host', None)
                if host:
                    logger.debug("profile %s uses host %s",
                                 profile_name, host)
                    args['host'] = host
                if boto.config.has_option(profile_name, 'is_secure'):
                    secure = boto.config.getbool(profile_name, 'is_secure',
                                                 'True')
                    args['is_secure'] = secure
                    logger.debug("profile %s is secure %s",
                                 profile_name, args['is_secure'])
                    if boto.config.has_section('Boto'):
                        secure = boto.config.getbool('Boto', 'is_secure', None)
                        self._is_secure_placeholder = secure
                        boto.config.remove_option('Boto', 'is_secure')
                if boto.config.has_option(profile_name, 'encrypt_keys'):
                    self.encrypt_keys = boto.config.getbool(profile_name, 'encrypt_keys')
                    logger.info("Encrypt option set in profile: " + str(self.encrypt_keys))
        else:
            """ not using a profile, check if port is set,
            because boto doesnt check"""
            port = boto.config.get('s3', 'port', None)
            if port:
                args['port'] = int(port)

        conn = boto.connect_s3(
            calling_format=boto.s3.connection.OrdinaryCallingFormat(),
            **args
        )

        if self._is_secure_placeholder is not None:
            secure = str(self._is_secure_placeholder)
            boto.config.set('Boto', 'is_secure', secure)
        return conn

    def hone_target(self, target):
        bucket, key = Radula.split_bucket(target)
        target_type = Radula.BUCKET
        false_bucket = False

        try:
            target = self.conn.get_bucket(bucket)
        except S3ResponseError:
            target = self.conn.get_bucket(bucket, validate=False)
            false_bucket = True
            pass

        try:
            if key:
                target_type = Radula.KEY
                if isinstance(key, Key):
                    target = key
                else:
                    if false_bucket:
                        target = Key(bucket=target, name=key)
                    else:
                        target = target.get_key(key)
        except S3ResponseError as e:
            logger.exception(e)
            raise

        return bucket, key, target, target_type


class Radula(RadulaClient):
    BUCKET = "bucket"
    KEY = "key"

    CANNED_ACLS = (
        'private',
        'public-read',
        'public-read-write',
        'authenticated-read',
        'bucket-owner-read',
        'bucket-owner-full-control',
    )

    @staticmethod
    def split_key(subject):
        """separate a target string into bucket and key parts,
        and require that key name not be empty"""
        return Radula.split_bucket(subject, require_key=True)

    @staticmethod
    def split_bucket(subject, require_key=False):
        """separate the bucket and key components from a string,
        such as mybucket/path/to/key. boto objects may also be
        given, and they already know their constituent pieces.
        """
        if isinstance(subject, Bucket):
            return subject, None
        if isinstance(subject, Key):
            return subject.bucket, subject

        s = subject.split('/', 1)
        if len(s) == 1:
            s.append(None)

        bucket_name, key_name = tuple(s)
        if require_key and not key_name:
            msg = "Invalid target, '{0}', contains no key name"
            raise RadulaError(msg.format(subject))

        return bucket_name, key_name

    def acls(self, **kwargs):
        print "Canned ACLs:"
        for acl in Radula.CANNED_ACLS:
            print acl

    def get_acl(self, **kwargs):
        """fetch a description of the ACL policy
        on a subject bucket or key"""
        subject = kwargs.get("subject", None)
        must_have(subject, "Subject (bucket/key) is needed")

        try:
            (bucket_name, key_name, subject,
             subject_type) = self.hone_target(subject)

            must_have(subject,
                      "Subject {0} '{1}' not found.",
                      subject_type, subject.name)

            policy = subject.get_acl()
            grants = self.format_policy(policy)
        except S3ResponseError as e:
            msg = "Subject {0} '{1}' raised S3ResponseError. {2}"
            raise RadulaError(msg.format(subject_type, subject.name,
                                         e.message))

        print "ACL for {0}: {1}".format(subject_type, subject.name)
        print grants

    def set_acl(self, **kwargs):
        """set the ACL policy
        on a subject bucket or key"""
        subject = kwargs.get("subject", None)
        must_have(subject, "Subject (bucket/key) is needed")
        target = kwargs.get("target", None)
        must_have(target and target in Radula.CANNED_ACLS,
                  "A canned ACL string is expected here. One of [{0}]",
                  ", ".join(Radula.CANNED_ACLS))

        try:
            (bucket_name, key_name, subject,
             subject_type) = self.hone_target(subject)
            sync_acl = subject_type == Radula.BUCKET

            must_have(subject,
                      "Subject {0} '{1}' not found.",
                      subject_type, subject.name)

            dry_run = kwargs.get("dry_run", False)
            if dry_run:
                dry_run_msg("set_acl", subject.name, "=>", target)
            else:
                subject.set_acl(target)
                policy = subject.get_acl()
                grants = self.format_policy(policy)
        except S3ResponseError as e:
            msg = "Subject {0} '{1}' raised S3ResponseError. {2}"
            msg = msg.format(subject_type, subject.name, e.message)
            raise RadulaError(msg)

        if not dry_run:
            print "ACL for {0}: {1}".format(subject_type, subject.name)
            print grants

        if sync_acl:
            self.sync_acl(subject=subject, dry_run=dry_run)

    @staticmethod
    def format_policy(policy):
        """format a ACL object to a readable string"""
        grants = []
        for g in policy.acl.grants:
            grant_type = g.type
            if g.id == policy.owner.id:
                grant_type = 'CanonicalUser:OWNER'
            if g.type == 'CanonicalUser':
                u = g.display_name
            elif g.type == 'Group':
                u = g.uri
            else:
                grant_type = "email_address"
                u = g.email_address
            fmt = "[{0}] {1} = {2}"
            grants.append(fmt.format(grant_type, u, g.permission))

        return "\n".join(sorted(grants))

    def compare_acl(self, **kwargs):
        """
        Compares bucket ACL to those of its keys, with a small report
        listing divergent policies
        """
        subject = kwargs.get("subject", None)
        must_have(subject, "Subject (bucket/key) is needed")

        bucket, key = self.split_bucket(subject)
        bucket = self.conn.get_bucket(bucket)

        if key:
            keys = [bucket.get_key(key)]
        else:
            keys = bucket

        bucket_acl = self.format_policy(bucket.get_acl())
        same = 0
        different = 0
        print "Bucket ACL for: {0}".format(bucket.name)
        print bucket_acl
        print "---------\n"

        for key in keys:
            key_acl = self.format_policy(key.get_acl())
            if key_acl == bucket_acl:
                same += 1
            else:
                different += 1
                print "Difference in {0}:".format(key.name)
                print key_acl
                print ""

        print "Keys with identical ACL: {0}".format(same)
        print "Keys with different ACL: {0}".format(different)

    def sync_acl(self, **kwargs):
        """
        Forces all keys in a bucket to adopt the bucket's ACL policy
        """
        subject = kwargs.get("subject", None)
        must_have(subject, "Subject (bucket/key) is needed")

        bucket, key = self.split_bucket(subject)
        if not isinstance(bucket, (Bucket,)):
            bucket = self.conn.get_bucket(bucket)
        bucket_policy = bucket.get_acl()
        bucket_acl = self.format_policy(bucket_policy)

        print "Bucket ACL for: {0}".format(bucket.name)
        print bucket_acl
        print "---------\n"

        if key:
            keys = [bucket.get_key(key)]
        else:
            keys = bucket

        dry_run = kwargs.get("dry_run", False)
        for key in keys:
            key_policy = key.get_acl()
            if (not dry_run and
                    key_policy and
                    bucket_policy and
                    key_policy.owner.id != bucket_policy.owner.id):
                        key = self.chown(key)

            msg = "Setting bucket's ACL on {0}".format(key.name)
            if dry_run:
                dry_run_msg('sync_acl', msg)
            else:
                print msg
                key.set_acl(bucket_policy)

    def chown(self, key):
        logger.warn("Changing ownership of key {0}".format(key.name))
        lib = RadulaLib(connection=self.conn)
        key_string = os.path.join(key.bucket.name, key.name)
        return lib.streaming_copy(key_string, key_string,
                                  force=True, verify=True)

    def allow(self, **kwargs):
        """alias of allow_user"""
        self.allow_user(**kwargs)

    def allow_user(self, **kwargs):
        """
        Grants a read or write permission to a user for a bucket or key.
        One or both of read or write are required to be truthy.
        This will guard against multiple entries for the same grants, which is
        prevalent on ceph-radosgw as well as aws-s3.
        Bucket action is recursive on keys unless apply_to_keys=False
        """
        user = kwargs.get("subject", None)
        must_have(user,
                  "User is required during permission grants")

        target = kwargs.get("target", None)
        must_have(target,
                  "A bucket or key is required during permission grants")

        read = kwargs.get("acl_read", None)
        write = kwargs.get("acl_write", None)
        threads = int(kwargs.get("threads", 0)) or Radula.DEFAULT_THREADS
        recurrance = kwargs.get("recurrance", False)
        if not any([read, write]):
            read = True

        bucket, key, target, target_type = self.hone_target(target)

        permissions = []
        if read:
            permissions.append("READ")
            permissions.append("READ_ACP")
        if write:
            permissions.append("WRITE")
            permissions.append("WRITE_ACP")

        policy = target.get_acl()
        acl = policy.acl

        dry_run = kwargs.get("dry_run", False)
        for permission in permissions:
            msg, add = self.__grant_check(
                acl.grants,
                user,
                permission,
                target_type,
                target.name)

            if dry_run:
                dry_run_msg('allow_user', msg)
            else:
                if not recurrance:
                    print msg
                if add:
                    acl.add_user_grant(permission, user)

        if dry_run:
            dry_run_msg('allow_user',
                        'setting new policy =>', target.name)
        else:
            target.set_acl(policy)
            msg = 'User {0} allowed {1} for {2} '.format(
                user,
                str(permissions),
                target.name
            )
            if recurrance:
                return msg
            else:
                print msg

        logger.info("target type: %s", target_type)
        if target_type == Radula.BUCKET:
            def mp_acl_args(rad, bucket, kwargs):
                for key in bucket:
                    kwargs_copy = kwargs.copy()
                    kwargs_copy.update({
                        "target": key,
                        "recurrance": True
                    })
                    yield(rad, RadulaACLChange.ALLOW, kwargs_copy)

            logger.warn("Starting recursive set_acl")
            pool = ParallelSim(processes=threads,
                               label="Set ACL progress")
            for args in mp_acl_args(self, target, kwargs):
                pool.add(do_mp_acl_set, args)

            pool.run()
            completed = pool.completed()
            must_have(completed, "Some ACL sets did not complete.")

    def __grant_check(self, grants, user, permission,
                      target_type, target_name):
        if self.is_granted(grants, user, permission):
            fmt = "User {0} already has {1} for {2} {3}, skipping"
            msg = fmt.format(user, permission, target_type, target_name)
            add = False
        else:
            fmt = "granting {0} to {1} on {2} {3}"
            msg = fmt.format(permission, user, target_type, target_name)
            add = True
        return (msg, add)

    def disallow(self, **kwargs):
        """alias of disallow_user"""
        self.disallow_user(**kwargs)

    def disallow_user(self, **kwargs):
        """
        Will remove a grant from a user for a bucket or key.
        If neither read or write are specified, BOTH are assumed.
        """
        user = kwargs.get("subject", None)
        must_have(user,
                  "User is required during permission grants")
        target = kwargs.get("target", None)
        must_have(target,
                  "A bucket or key is required during permission grants")
        threads = int(kwargs.get("threads", 0)) or Radula.DEFAULT_THREADS
        recurrance = kwargs.get("recurrance", False)

        permissions = []
        if kwargs.get("acl_read", None):
            permissions.append("READ")
        if kwargs.get("acl_write", None):
            permissions.append("WRITE")
        if not len(permissions):
            permissions = ['READ', 'WRITE', 'READ_ACP',
                           'WRITE_ACP', 'FULL_CONTROL']

        bucket, key, target, target_type = self.hone_target(target)

        if target_type == Radula.BUCKET:
            def mp_acl_args(rad, bucket, kwargs):
                for key in bucket:
                    kwargs_copy = kwargs.copy()
                    kwargs_copy.update({
                        "target": key,
                        "recurrance": True
                    })
                    yield(rad, RadulaACLChange.DISALLOW, kwargs_copy)

            logger.warn("Starting recursive set_acl")
            pool = ParallelSim(processes=threads,
                               label="Set ACL progress")
            for args in mp_acl_args(self, target, kwargs):
                pool.add(do_mp_acl_set, args)

            pool.run()
            completed = pool.completed()
            must_have(completed, "Some ACL sets did not complete.")

        policy = target.get_acl()
        acl = policy.acl

        dry_run = kwargs.get("dry_run", False)
        grant_count = len(acl.grants)
        acl_args = (user, permissions, policy.owner.id,
                    target, dry_run, recurrance)
        acl.grants = [g for g in acl.grants if self.grant_filter(g, *acl_args)]
        if len(acl.grants) != grant_count:
            if dry_run:
                dry_run_msg('disallow_user',
                            'setting new policy =>', target.name)
            else:
                target.set_acl(policy)
        else:
            msg = "No change for {0} {1}".format(target_type, target.name)
            if dry_run:
                dry_run_msg('disallow_user', msg)
            else:
                print msg

    @staticmethod
    def is_granted(grants, user, permission):
        """
        True when the user+permission appears in the list of grants.
        """
        for grant in grants:
            if grant.id == user and grant.permission == permission:
                return True
        return False

    @staticmethod
    def grant_filter(grant, user, permissions, owner,
                     subject, dry_run, recurrance=False):
        """
        Grant filter function, returning True for items that should be kept.
        Grants for the policy owner are kept.
        Only grants matching the user and permissions
        we wish to eliminate are tossed (False).
        """
        # don't restrict the owner; suspend them instead (but not here)
        if user and user == owner:
            return True
        if grant.id != user:
            return True
        if grant.permission in permissions:
            fmt = "Grant dropped: user={0}, permission={1} on {2}"
            msg = fmt.format(grant.id, grant.permission, subject.name)
            if dry_run:
                dry_run_msg('grant_filter', msg)
            else:
                if not recurrance:
                    print msg
            return False
        return True

    def profiles(self, **kwargs):
        cfg = boto.config
        profile_list = []
        boto_default_profile = 'Credentials'
        profile_found = False
        selected_profile = kwargs.get("profile", None) or boto_default_profile

        for sec in [sec for sec in cfg.sections() if cfg.has_option(sec, 'aws_access_key_id')]:
            sec = sec.split(" ")[-1]
            found = sec == selected_profile
            if found:
                profile_found = True

            if sec == boto_default_profile:
                sec = 'DEFAULT'
            profile_list.append((sec, found))

        for profile, selected in profile_list:
            used = ' '
            if selected:
                used = '*'
            print " ".join([used, profile])

        if not profile_found:
            logger.warning("Selected profile (%s) not found!", selected_profile)


class RadulaLib(RadulaClient):
    PROGRESS_CHUNKS = 20
    chunk_size = Radula.DEFAULT_CHUNK

    def make_bucket(self, bucket, dry_run=False):
        """proxy make_bucket in boto"""
        for existing_bucket in self.conn.get_all_buckets():
            if bucket == existing_bucket.name:
                print "Bucket {0} already exists.".format(bucket)
                return False

        if dry_run:
            return dry_run_msg('make_bucket', bucket)
        return self.conn.create_bucket(bucket)

    def remove_bucket(self, bucket, dry_run=False):
        """proxy delete_bucket in boto"""
        if dry_run:
            return dry_run_msg('remove_bucket', bucket)
        return self.conn.delete_bucket(bucket)

    def get_buckets(self):
        """proxy get_all_buckets in boto"""
        return self.conn.get_all_buckets()

    def remove_key(self, subject, dry_run=False):
        """proxy delete_key in boto"""
        bucket_name, key_name = Radula.split_key(subject)
        bucket = self.conn.get_bucket(bucket_name)
        for key in self.keys(subject):
            if dry_run:
                yield dry_run_msg('remove_key', os.path.join(bucket_name, key))
            else:
                bucket.delete_key(key)
                yield key

    def upload(self, subject, target, verify=False,
               resume=False, force=False, dry_run=False, encrypt=None):
        """initiate multipart uploads of
        potential plural local subject files"""
        bucket_name, target_key = Radula.split_bucket(target)
        if encrypt is None:
            encrypt = self.encrypt_keys

        try:
            bucket = self.conn.get_bucket(bucket_name)
            files = glob(subject)
            if len(files) == 0:
                msg = "No file(s) to upload: used {0}"
                raise RadulaError(msg.format(subject))

            key_names = [guess_target_name(f, target_key) for f in files]
            if not force:
                self.assert_missing_target(bucket, key_names)

                if not resume:
                    self.assert_missing_mpu(bucket, key_names)

            for source_path in files:
                key_name = guess_target_name(source_path, target_key)
                if dry_run:
                    dry_run_msg('upload', source_path, "=>", key_name)
                else:
                    logger.debug("def upload encrypt=" + str(encrypt))
                    started = self._start_upload(
                        source_path,
                        bucket,
                        key_name,
                        verify=verify,
                        resume=resume,
                        encrypt=encrypt)
                    must_have(started, "{0} did not correctly upload",
                              source_path)
        except S3ResponseError as e:
            msg = "Subject {0} '{1}' raised S3ResponseError. {2}"
            raise RadulaError(msg.format(bucket_name, target_key, e.message))

    def _start_upload(self, source, bucket, key_name, verify=False,
                      resume=False, copy_from_key=False, dest_conn=None,
                      encrypt=None):
        if copy_from_key:
            source_name = source
            source_size = source.size
            num_parts, chunk_size, strategy = self._remote_chunk_size(source)
        else:
            source_name = source
            source = open(source, 'rb')
            source_size = file_size(source)
            strategy = RadulaChunkStrategy.DEFAULT
            num_parts, chunk_size = self.calculate_chunks(source_size, strategy)

        logger.info("CHUNKS: %d parts x %s", num_parts, human_size(chunk_size))

        generate_hashes = strategy == RadulaChunkStrategy.LEGACY

        metadata = {
            RadulaHeaders.get('version'): __version__,
            RadulaHeaders.get("parts"): num_parts,
            RadulaHeaders.get("chunk_size"): chunk_size,
        }

        hashes = None
        if num_parts == 1:
            key, part_hash = self._single_part_upload(
                source,
                key_name,
                bucket,
                copy_from_key=copy_from_key,
                source_size=source_size,
                metadata=metadata,
                generate_hashes=generate_hashes,
                encrypt=encrypt)

            hashes = [part_hash]

        else:
            try:
                key, hashes = self._multi_part_upload(
                    source,
                    key_name,
                    bucket=bucket,
                    copy_from_key=copy_from_key,
                    source_size=source_size,
                    num_parts=num_parts,
                    chunk_size=chunk_size,
                    dest_conn=dest_conn,
                    metadata=metadata,
                    resume=resume,
                    generate_hashes=generate_hashes,
                    encrypt=encrypt)
            except:
                logger.error("Error during upload or cancelling upload",
                             exc_info=True)
                raise

        if not copy_from_key and not verify:
            return True
        elif copy_from_key and verify:
            return self.verify_keys(source, key, dest_conn)
        else:
            return self.verify(source_name, key, copy_from_key, hashes)

    def _single_part_upload(self, source, key_name, bucket,
                            copy_from_key=False, source_size=0,
                            metadata=None, generate_hashes=False,
                            encrypt=None):
        t1 = time.time()
        part_hash = None

        logger.debug("Encrypt is " + str(encrypt))

        if copy_from_key:
            data = source.get_contents_as_string()
            key = bucket.new_key(key_name)
            if metadata is not None:
                for k, val in metadata.items():
                    key.set_metadata(k, val)
            fake_fp = StringIO(data)
            part_hash, b64_digest = Key.compute_md5(Key(), fake_fp)
            key.set_contents_from_string(data, encrypt_key=encrypt)
        else:
            source.seek(0)
            key = bucket.new_key(key_name)
            if metadata is not None:
                for k, val in metadata.items():
                    key.set_metadata(k, val)
            key.set_contents_from_file(source, encrypt_key=encrypt)

        t2 = time.time() - t1

        key = bucket.get_key(key_name)
        self.sync_acl(key, bucket)
        print_timings(source_size, t2, "uploading")
        print_url(key)
        return key, part_hash

    def _multi_part_upload(self, source, key_name, bucket,
                           copy_from_key=False, source_size=0, num_parts=0,
                           chunk_size=0, dest_conn=None,
                           metadata=None, resume=False,
                           generate_hashes=False,
                           encrypt=None):
        """multipart upload strategy.
        Borrowed heavily from the work of David Arthur
        https://github.com/mumrah/s3-multipart
        """
        dest_conn = dest_conn or self.conn

        mpu_init = self._init_mpu(bucket, key_name, dest_conn,
                                  metadata, resume, encrypt)

        (mpu, existing_parts) = mpu_init

        msg = "Starting upload: %s (%s)"
        logger.info(msg % (mpu.id, human_size(source_size)))
        pool = None

        def cancel_upload():
            if pool:
                pool.terminate()

            # # Canceling uploads will remove uploaded parts.
            # # Not cancelling lets them resume.
            # mpu.cancel_upload()
        try:
            # Create a pool of workers
            logger.info("ParallelSim with %d threads", self.thread_count)
            pool = ParallelSim(processes=self.thread_count,
                               label="Upload Progress")

            args = (source, bucket, mpu, chunk_size, num_parts,
                    copy_from_key, dest_conn, existing_parts,
                    generate_hashes)

            upload_arg_gen = self._mp_upload_args(*args)
            for args in upload_arg_gen:
                pool.add(do_part_upload, args)

            pool.run()
            completed = pool.completed()
            not_completed_msg = """Multipart upload tasks completed,
                  but not all parts called back. Try resuming."""
            must_have(completed, not_completed_msg)

            mpu.complete_upload()
        except KeyboardInterrupt:
            logger.warn("Received KeyboardInterrupt, cancelling upload")
            cancel_upload()
            raise
        except Exception:
            logger.error("Encountered an error, cancelling upload",
                         exc_info=True)
            cancel_upload()
            raise

        key = bucket.get_key(key_name)
        self.sync_acl(key, bucket)
        print_timings(source_size, pool.get_timing(), "uploading")
        print_url(key)
        hashes = None
        if generate_hashes:
            hashes = sorted(pool.get_results(), key=lambda d: d[0])
        return key, hashes

    def _init_mpu(self, bucket, key_name, dest_conn, metadata, resume=False,
                  encrypt=None):
        key_path = os.path.join(bucket.name, key_name)

        existing_parts = {}
        mpu = None
        logger.debug("Final resume: %s", resume)
        if resume:
            logger.info("Checking existing parts..")
            mpu = self.find_multipart_upload(key_path, dest_conn)
            if mpu:
                logger.info("Recovered upload in progress: mpu.id %s", mpu.id)
                for part in mpu:
                    logger.info("PART %s = %s", part.part_number, part.etag)
                    existing_parts[part.part_number] = part.etag

        if not mpu:
            logger.info("Initializing Multipart upload")
            mpu = bucket.initiate_multipart_upload(
                key_name,
                metadata=metadata,
                encrypt_key=encrypt
            )

        return mpu, existing_parts

    def _mp_verify_args(self, source, dest, chunk_size, total_parts):
        for part_num in range(total_parts):
            chunk_start = chunk_size * part_num
            process_args = (
                source,
                dest,
                part_num,
                chunk_start,
                chunk_size,
                total_parts
            )
            yield process_args

    def _mp_upload_args(self, source, bucket, mpu, chunk_size, total_parts,
                        copy, dest_conn, existing_parts=None,
                        generate_hashes=False):
        """Generate arguments for invocations of do_part_upload"""
        existing_parts = existing_parts or {}
        for part_num in range(total_parts):
            chunk_start = chunk_size * part_num
            if copy:
                name = (source.bucket.name, source.name)
            else:
                name = source.name

            process_args = (
                self.conn,
                bucket.name,
                mpu,
                name,
                part_num,
                chunk_start,
                chunk_size,
                total_parts,
                copy,
                dest_conn,
                existing_parts.get(part_num + 1, None),
                generate_hashes,
            )

            yield process_args

    def _mp_download_args(self, key, target, num_parts, chunk_size):
        for part_num in range(num_parts):
            chunk_start = chunk_size * part_num
            process_args = (
                self.conn,
                key,
                target,
                part_num,
                chunk_start,
                chunk_size,
                num_parts
            )
            yield process_args

    def _mp_rehash_args(self, key, num_parts, chunk_size):
        for part_num in range(num_parts):
            chunk_start = chunk_size * part_num
            process_args = (self.conn, key, part_num,
                            chunk_start, chunk_size, num_parts)
            yield process_args

    def assert_missing_target(self, bucket, key_names):
        for key_name in key_names:
            key = bucket.get_key(key_name)
            if key:
                msg = "Key {0}/{1} already exists. Use -f,--force to overwrite"
                raise RadulaError(msg.format(bucket.name, key_name))

    def assert_missing_mpu(self, bucket, key_names):
        for key_name in key_names:
            mpu = self.find_multipart_upload("/".join([bucket.name, key_name]))
            if mpu:
                msg = "Multipart Upload for {0}/{1} in progress. " \
                      "Use -z,--resume if needed"
                raise RadulaError(msg.format(bucket.name, key_name))

    @staticmethod
    def sync_acl(key, bucket):
        bucket_policy = bucket.get_acl()
        bucket_owner = bucket_policy.owner.id
        key_policy = key.get_acl()
        key_owner = key_policy.owner.id

        if key_owner == bucket_owner:
            if bucket_policy.acl:
                key.set_acl(bucket_policy)
        else:
            grants = bucket_policy.acl.grants
            key_policy.acl.grants = grants
            key.set_acl(key_policy)

            for permission in ['FULL_CONTROL']:
                if not Radula.is_granted(key_policy.acl.grants,
                                         bucket_owner, permission):
                    key_policy.acl.add_user_grant(permission, bucket_owner)
                    key.set_acl(key_policy)

    def download(self, subject, target, verify=False,
                 force=False, dry_run=False):
        """proxy download in boto, guarding overwrites"""
        try:
            basename = os.path.basename(subject)
            target = target or basename

            if os.path.isdir(target):
                target = "/".join([target, basename])

            if os.path.isfile(target) and not force:
                fmt = "local target file exists (use -f to overwrite): {0}"
                raise RadulaError(fmt.format(target))

            (bucket_name, key_name, key,
             subject_type) = self.hone_target(subject)

            must_have(subject_type == Radula.KEY,
                      "Key not found: {0}", key_name)
            must_have(key, "Key not found: {0}", key_name)

            logger.debug({
                "size": key.size,
                "chunk": self.chunk_size,
                "threads": self.thread_count,
            })

            if dry_run:
                dry_run_msg(
                    'download', RadulaLib._key_name(key, long_key=True),
                    "=>", target
                )
                return True
            else:
                if key.size <= self.chunk_size:
                    self._single_part_download(key, target)
                else:
                    self._multipart_download(key, target)

                if not verify:
                    return True

                return self.verify(target, key)

        except S3ResponseError as e:
            msg = "Subject {0} '{1}' raised S3ResponseError. {2}"
            raise RadulaError(msg.format(bucket_name, key_name, e.message))

    def _single_part_download(self, key, target):
        def progress_callback(a, b):
            percentage = 0
            if a:
                percentage = 100 * (float(a) / float(b))
            print "Download Progress: %.2f%%" % percentage

        t1 = time.time()
        key.get_contents_to_filename(target, cb=progress_callback,
                                     num_cb=self.PROGRESS_CHUNKS)
        t2 = time.time()
        print_timings(key.size, t2 - t1, "downloading")
        return True

    def _multipart_download(self, key, target):
        msg = "Starting download: %s (%s)"
        logger.info(msg % (key.name, human_size(key.size)))
        pool = None
        num_parts, chunk_size = self.calculate_chunks(key.size)

        if os.path.exists(target):
            if not os.path.isfile(target):
                msg = "target {0} exists, but is not a file"
                raise RadulaError(msg.format(target))
        else:
            # touch file.
            with open(target, 'a'):
                pass

        def cancel_download():
            if pool:
                pool.terminate()

        try:
            # Create a pool of workers
            logger.info("ParallelSim with %d threads", self.thread_count)

            pool = ParallelSim(processes=self.thread_count,
                               label="Download Progress")
            download_args = self._mp_download_args(key, target,
                                                   num_parts, chunk_size)
            for args in download_args:
                pool.add(do_part_download, args)

            pool.run()
            completed = pool.completed()
            not_completed_msg = "Multipart download tasks completed, " \
                                "but completed was False??."
            must_have(completed, not_completed_msg)

            try:
                mod_time = datetime.strptime(
                    key.last_modified,
                    '%a, %d %b %Y %H:%M:%S %Z'
                )

                mod_time = to_timestamp(mod_time)
                os.utime(target, (mod_time, mod_time))

            except ValueError as e:
                logger.exception(e)
                logger.warn(" ".join([
                    "datetime ValueError encountered,",
                    "but not a critical error."
                ]))

        except KeyboardInterrupt:
            logger.warn("Received KeyboardInterrupt, cancelling download")
            cancel_download()
            raise
        except Exception:
            msg = "Encountered an error, cancelling download"
            logger.error(msg, exc_info=True)
            cancel_download()
            raise

        if pool:
            print_timings(key.size, pool.get_timing(), "downloading")

        return key

    def _single_part_rehash(self, key):
        def progress_callback(a, b):
            percentage = 0
            if a:
                percentage = 100 * (float(a) / float(b))
            print "Download Progress: %.2f%%" % percentage

        t1 = time.time()
        hash_obj = md5()
        hash_obj.update(key.get_contents_as_string(cb=progress_callback, num_cb=self.PROGRESS_CHUNKS))
        hex_digest = hash_obj.hexdigest()
        t2 = time.time()
        print_timings(key.size, t2 - t1, "downloading")
        return hex_digest

    def _multipart_rehash(self, key, num_parts, chunk_size):
        msg = "Starting download: %s (%s)"
        logger.info(msg % (key.name, human_size(key.size)))
        pool = None

        def cancel_download():
            if pool:
                pool.terminate()

        try:
            # Create a pool of workers
            logger.info("ParallelSim with %d threads", self.thread_count)

            pool = ParallelSim(processes=self.thread_count,
                               label="Download Progress")
            download_args = self._mp_rehash_args(key, num_parts, chunk_size)
            for args in download_args:
                pool.add(do_part_rehash, args)

            pool.run()
            completed = pool.completed()
            not_completed_msg = "Multipart download tasks completed, " \
                                "but completed was False??."
            must_have(completed, not_completed_msg)
        except KeyboardInterrupt:
            logger.warn("Received KeyboardInterrupt, cancelling download")
            cancel_download()
            raise
        except Exception:
            msg = "Encountered an error, cancelling download"
            logger.error(msg, exc_info=True)
            cancel_download()
            raise

        if pool:
            print_timings(key.size, pool.get_timing(), "downloading")

        hash_obj = md5()
        results = sorted(pool.get_results(), key=lambda d: d[0])
        hash_obj.update(''.join([r[1] for r in results]))
        hex_digest = hash_obj.hexdigest()

        if num_parts == 1:
            return hex_digest
        return '{0}-{1}'.format(hex_digest, num_parts)

    def cat(self, subject, chunk_size=None):
        """print remote file to stdout"""
        bucket_name, key_name = Radula.split_key(subject)
        boto_key = self.conn.get_bucket(bucket_name).get_key(key_name)
        must_have(boto_key, "Key not found: {0}", key_name)

        headers = None
        if chunk_size:
            headers = {
                'Range': "bytes=%s" % (chunk_size)
            }

        sys.stdout.write(boto_key.get_contents_as_string(headers=headers))

    def keys(self, subject, long_key=False):
        """list keys in a bucket with consideration
        of glob patterns if provided"""
        if not getattr(subject, "__iter__", False):
            subject = [subject]
        for sub in subject:
            bucket_name, pattern = Radula.split_bucket(sub)
            bucket = self.conn.get_bucket(bucket_name)
            if not pattern:
                for key in bucket:
                    yield RadulaLib._key_name(key.name, bucket_name, long_key)
                return

            for matching_keys in RadulaLib.__key_buffer(bucket, pattern):
                for key in matching_keys:
                    yield RadulaLib._key_name(key, bucket_name, long_key)

    @staticmethod
    def __key_buffer(bucket, pattern, buffer_size=256):
        buffer_keys = []
        for k in bucket:
            buffer_keys.append(k.name)
            if len(buffer_keys) >= buffer_size:
                filtered_keys = fnmatch.filter(buffer_keys, pattern)
                if len(filtered_keys):
                    yield filtered_keys
                buffer_keys = []
        yield fnmatch.filter(buffer_keys, pattern)

    @staticmethod
    def _key_name(key, bucket=None, long_key=False):
        if isinstance(key, Key):
            bucket = bucket or key.bucket
            key = key.name

        if isinstance(bucket, Bucket):
            bucket = bucket.name

        if long_key:
            return os.path.join(bucket, key)
        return key

    def info(self, subject):
        """fetch metadata of a remote subject key"""
        bucket_name, key_name = Radula.split_bucket(subject)
        bucket = self.conn.get_bucket(bucket_name)

        if key_name:
            key = bucket.get_key(key_name)
            must_have(key, "Key not found: {0}", key_name)
            key.bucket = bucket_name
            return vars(key)

        total_size = 0
        object_count = 0
        largest = {"obj": None, "val": None}
        newest = {"obj": None, "val": None}
        oldest = {"obj": None, "val": None}
        for key in bucket:
            lv = largest.get("val")
            nm = newest.get("val")
            om = oldest.get("val")

            object_count += 1
            total_size += key.size
            if lv is None or key.size > lv:
                largest["obj"] = key.name
                largest["val"] = key.size

            d = datetime.strptime(key.last_modified.split(".")[0],
                                  "%Y-%m-%dT%H:%M:%S")
            if nm is None or d > nm:
                newest["obj"] = key.name
                newest["val"] = d
            if om is None or d < om:
                oldest["obj"] = key.name
                oldest["val"] = d

        return {
            "size": total_size,
            "size_human": human_size(total_size),
            "keys": {
                "count": object_count,
                "largest": largest.get("obj", None),
                "newest": newest.get("obj", None),
                "oldest": oldest.get("obj", None),
            }
        }

    def remote_md5(self, subject):
        """fetch hash from metadata of a remote subject key"""
        if isinstance(subject, boto.s3.key.Key):
            return subject.etag.translate(None, '"')
        else:
            (bucket_name, key_name, key,
             subject_type) = self.hone_target(subject)

            if subject_type != Radula.KEY:
                msg = 'Remote target is not a key! ({0})'
                raise RadulaError(msg.format(subject))

            try:
                must_have(key, "Remote file '{0}' not found", subject)
                return key.etag.translate(None, '"')
            except Exception as e:
                logger.info("bucket: " + bucket_name)
                logger.info("key_name: " + key_name)
                logger.error(e.message, exc_info=True)
                raise

    def remote_rehash(self, subject):
        expected = self.remote_md5(subject)

        (bucket_name, key_name,
            key, subject_type) = self.hone_target(subject)

        must_have(subject_type == Radula.KEY, "Key not found: {0}", key_name)
        must_have(key, "Key not found: {0}", key_name)

        num_parts, chunk_size, strategy = self._remote_chunk_size(key)

        logger.debug({
            "size": key.size,
            "chunk": self.chunk_size,
            "threads": self.thread_count,
        })

        try:
            if key.size <= self.chunk_size:
                hex_digest = self._single_part_rehash(key)
            else:
                hex_digest = self._multipart_rehash(key, num_parts, chunk_size)
        except S3ResponseError as e:
            msg = "Subject {0} '{1}' raised S3ResponseError. {2}"
            raise RadulaError(msg.format(bucket_name, key_name, e.message))

        logger.debug("Expected: %s, Received: %s", expected, hex_digest)
        if expected == hex_digest:
            logger.info("Checksum Verified!")
            msg = "RemoteMetaData and newly computed hash @ {0}"
            logger.info(msg.format(hex_digest))
            return True
        else:
            msg = "RemoteMetaData: {0} ; ComputedHash: {1}"
            logger.error(msg.format(expected, hex_digest))
            fmt = "DIFFERENT CKSUMS!\nRemoteMetaData {0}\nComputedHash {1}"
            print >> sys.stderr, fmt.format(expected, hex_digest)
            return False

    def multipart_info(self, subject):
        if isinstance(subject, boto.s3.key.Key):
            items = {}
            for k, v in subject.metadata.items():
                if k in RadulaHeaders.values():
                    items[k] = v
            return items
        else:
            bucket_name, key_name = Radula.split_key(subject)
            try:
                bucket = self.conn.get_bucket(bucket_name)
                key = bucket.get_key(key_name)
                must_have(key, "Remote file '{0}' not found", subject)
                return self.multipart_info(key)
            except Exception as e:
                logger.info("bucket: " + bucket_name)
                logger.info("key_name: " + key_name)
                logger.error(e.message, exc_info=True)
                raise

    def calculate_chunks(self, source_size,
                         strategy=RadulaChunkStrategy.DEFAULT):
        if strategy == RadulaChunkStrategy.LEGACY:
            logger.debug("delegating to legacy chunk strategy")
            return legacy_calculate_chunks(source_size)

        logger.debug("chunk_size: %d", self.chunk_size)
        if self.chunk_size:
            return calculate_num_chunks(source_size, self.chunk_size)

        return calculate_chunks(source_size)

    def local_md5(self, subject, chunk_size=0):
        """performs a multi-threaded hash of a local subject file"""
        must_have(os.path.isfile(subject),
                  "Local file '{0}' not found",
                  subject)
        hash_obj = md5()

        strategy = RadulaChunkStrategy.DEFAULT
        if not chunk_size:
            strategy = RadulaChunkStrategy.LEGACY

        with open(subject, 'rb') as source_file:
            source_size = file_size(source_file)
            if chunk_size:
                self.chunk_size = chunk_size

            num_parts, chunk_size = self.calculate_chunks(source_size,
                                                          strategy)
            key = Key()

            logger.debug("local-md5 parts: %d", num_parts)
            if num_parts == 1:
                source_file.seek(0)
                hash_obj.update(source_file.read(source_size))
            else:
                def gen_args(num):
                    for n in xrange(num):
                        yield (subject, n, chunk_size, key)

                logger.info("ParallelSim with %d threads", self.thread_count)
                pool = ParallelSim(processes=self.thread_count,
                                   label="Local MD5")
                for args in gen_args(num_parts):
                    pool.add(do_part_cksum, args)
                pool.run()

                print_timings(source_size, pool.get_timing(), "hashing")
                results = sorted(pool.get_results(), key=lambda d: d[0])
                hash_obj.update(''.join([r[1] for r in results]))

        hex_digest = hash_obj.hexdigest()
        if num_parts == 1:
            return hex_digest
        return '{0}-{1}'.format(hex_digest, num_parts)

    def verify_keys(self, source, destination, dest_conn=None, dest_profile=None):
        """compares hashes of two keys by downloading and hashing chunks
        """
        source_bucket_name, source_key_name = Radula.split_bucket(source)
        source_bucket = self.conn.get_bucket(source_bucket_name)
        source_key = source_bucket.get_key(source_key_name)
        if source_key is None:
            raise RadulaError("source key does not exist")

        if dest_conn is None:
            dest_conn = self.new_connection(dest_profile)
        dest_bucket_name, dest_key_name = Radula.split_bucket(destination)
        dest_bucket = dest_conn.get_bucket(dest_bucket_name)
        dest_key = dest_bucket.get_key(dest_key_name)
        if dest_key is None:
            raise RadulaError("destination key does not exist")

        source_size = source_key.size
        dest_size = dest_key.size
        if source_size != dest_size:
            msg = "source and destination keys are different size, bailing out"
            raise RadulaError(msg)

        num_parts, chunk_size = self.calculate_chunks(source_size)
        logger.info("CHUNKS: %d parts x %s", num_parts, human_size(chunk_size))

        if num_parts == 1:
            source_data = source_key.get_contents_as_string()
            dest_data = dest_key.get_contents_as_string()
            if source_data != dest_data:
                raise RadulaError("single part verify: data does not match!")
        else:
            def cancel_upload():
                if pool:
                    pool.terminate()
            try:
                logger.info("ParallelSim with %d threads", self.thread_count)
                pool = ParallelSim(processes=self.thread_count,
                                   label="Verify Keys Progress")

                args = (source_key, dest_key, chunk_size, num_parts)
                verify_arg_gen = self._mp_verify_args(*args)
                for args in verify_arg_gen:
                    pool.add(do_part_verify, args)
                pool.run()
                must_have(pool.completed(), "Some parts failed to call back")
            except KeyboardInterrupt:
                logger.warn("Received KeyboardInterrupt, cancelling upload")
                cancel_upload()
                raise
            except Exception:
                logger.error("Encountered an error, cancelling upload",
                             exc_info=True)
                cancel_upload()
                raise

        logger.info("Key data matches!")
        return True

    def verify(self, subject, target, copy=False, hashes=None):
        """compares hashes of a local subject and a remote target
        or those of two remote targets
        """
        (bucket_name, key_name, _subject,
         _subject_type) = self.hone_target(target)

        if isinstance(target, (str, unicode)):
            target_key = guess_target_name(subject, key_name)
            target = "/".join([bucket_name, target_key])

        remote_md5 = self.remote_md5(target)
        if copy:
            logger.info('Verifying hashes by comparing source and dest object etags')
            local_md5 = self.remote_md5(subject)
            if local_md5 != remote_md5 and hashes:
                logger.info('Etags did not match! Verifying hashes generated from data in motion')
                if len(hashes) == 1:
                    local_md5 = hashes[0]
                else:
                    hash_obj = md5()
                    hash_obj.update(''.join([r[1] for r in hashes]))
                    hex_digest = hash_obj.hexdigest()
                    local_md5 = '{0}-{1}'.format(hex_digest, len(hashes))
        else:
            (bucket_name, key_name, key,
             subject_type) = self.hone_target(target)

            if subject_type != Radula.KEY:
                msg = 'Remote target is not a key! ({0})'
                raise RadulaError(msg.format(subject))

            num_parts, chunk_size, strategy = self._remote_chunk_size(key)
            logger.info("remote object reports chunk size: %s", chunk_size)
            local_md5 = self.local_md5(subject, int(chunk_size))

        if local_md5 == remote_md5:
            logger.info("Checksum Verified!")
            logger.info("Local and remote targets @ {0}".format(local_md5))
            return True
        else:
            msg = "LocalMD5: {0} ; RemoteMD5: {1}"
            logger.error(msg.format(local_md5, remote_md5))
            fmt = "DIFFERENT CKSUMS!\nLocal {0}\nRemote {1}"
            print >> sys.stderr, fmt.format(local_md5, remote_md5)
            return False

    def multipart_list(self, subject, conn=None):
        """lists lingering multipart upload parts """
        bucket_name, key_name = Radula.split_bucket(subject)
        conn = conn or self.conn
        bucket = conn.get_bucket(bucket_name)

        uploads = bucket.list_multipart_uploads()
        if key_name:
            uploads = [up for up in uploads if up.key_name == key_name]

        return bucket, uploads

    def find_multipart_upload(self, subject, conn=None):
        bucket, key = Radula.split_bucket(subject, require_key=True)
        _buck, uploads = self.multipart_list(bucket, conn)
        for up in uploads:
            key_name = key
            bucket_name = bucket
            if isinstance(key, Key):
                key_name = key.name
            if isinstance(bucket, Bucket):
                bucket_name = bucket.name
            if up.bucket.name == bucket_name and up.key_name == key_name:
                return up
        return None

    def multipart_clean(self, subject):
        """alias of multipart_clean"""
        bucket, uploads = self.multipart_list(subject)
        for up in uploads:
            logger.info("Canceling {0} {1}".format(up.key_name, up.id))
            bucket.cancel_multipart_upload(up.key_name, up.id)
        return True

    def streaming_copy(self, source, destination, dest_profile=None,
                       force=False, verify=False, resume=False, dry_run=False,
                       encrypt=None):
        """initiate streaming copy between two keys"""
        if encrypt is None:
            encrypt = self.encrypt_keys
        source_bucket_name, source_key_name = Radula.split_bucket(source)
        source_bucket = self.conn.get_bucket(source_bucket_name)
        source_key = source_bucket.get_key(source_key_name)
        if source_key is None:
            raise RadulaError("source key does not exist")

        if dest_profile is not None:
            if dest_profile == 'Default':
                dest_conn = self.new_connection()
            else:
                dest_conn = self.new_connection(dest_profile)
        else:
            dest_conn = self.conn

        dest_bucket_name, dest_key_name = Radula.split_bucket(destination)
        dest_key_name = guess_target_name(source, dest_key_name)

        dest_bucket = dest_conn.get_bucket(dest_bucket_name, validate=False)
        dest_key = dest_bucket.get_key(dest_key_name)
        if dest_key is not None and not force:
            raise RadulaError("dest key exists (use -f to overwrite)")

        if dry_run:
            dry_run_msg(
                'download', RadulaLib._key_name(source_key, long_key=True),
                "=>", RadulaLib._key_name(dest_key, long_key=True),
            )
        else:
            started = self._start_upload(
                source_key,
                dest_bucket,
                dest_key_name,
                verify=verify,
                resume=resume,
                copy_from_key=True,
                dest_conn=dest_conn,
                encrypt=encrypt)

            must_have(started,
                      "{0} did not correctly upload", source)

        return dest_key

    def _remote_chunk_size(self, source):
        remote_mp_info = self.multipart_info(source)

        if RadulaHeaders.get('chunk_size') in remote_mp_info:
            # if the chunk size is in the metadata, we're going to use it
            chunk_size_parts = remote_mp_info.get(RadulaHeaders.get('chunk_size'), 0).split('.')
            if len(chunk_size_parts) > 1 and int(chunk_size_parts[1]) > 0:
                raise ValueError("chunk size is a float with a non-zero remainder")

            chunk_size = int(chunk_size_parts[0])

            msg = "Found chunk_size {size} in source metadata"
            logger.info(msg.format(size=chunk_size))
            # NOTE no "self" here
            num_parts, chunk_size = calculate_chunks(source.size, chunk_size)
            return num_parts, chunk_size, RadulaChunkStrategy.DEFAULT
        else:
            # chunk size isnt in metadata, so use LEGACY strategy to look it up
            strategy = RadulaChunkStrategy.LEGACY
            logger.info("Attempting to match the source object's LEGACY chunk strategy")
            num_parts, chunk_size = self.calculate_chunks(source.size, strategy=strategy)
            return num_parts, chunk_size, strategy


def human_size(size, precision=2):
    """humanized units, ripped from the net"""
    suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    suffix_index = 0
    while size >= 1000:
        suffix_index += 1

        size /= 1000.0
    return "%.*f %s" % (precision, size, suffixes[suffix_index])


def from_human_size(size, minimum=0, default=Radula.DEFAULT_CHUNK,
                    bounds=True, accept_range=False):
    """bytes from humanized units"""

    if accept_range:
        def recur(s):
            return from_human_size(
                s, minimum=minimum, default=default,
                bounds=bounds, accept_range=False)

        if '-' in size:
            byte_ranges = map(recur, size.split('-'))
            end_is_int = isinstance(byte_ranges[1], (int,))
            if end_is_int and byte_ranges[1] < byte_ranges[0]:
                raise ValueError("Invalid byte range: %s" % (byte_ranges,))
        else:
            byte_ranges = [0, recur(size) - 1]
        return '-'.join(map(str, byte_ranges))

    logger.debug("from_human_size input: %s", size)
    parts = re.split('(\d+)', size)
    logger.debug("from_human_size parts: %s", parts)

    if len(parts) == 2:
        size = parts[2]
    elif len(parts) == 3:
        # sizes in bytes
        suffixes = {
            '': 1,
            'B': 1,
            'K': 1000,
            'KB': 1000,
            'KIB': 1024,
            'M': 1000 * 1000,
            'MB': 1000 * 1000,
            'MIB': 1024 * 1024,
            'G': 1000 * 1000 * 1000,
            'GB': 1000 * 1000 * 1000,
            'GIB': 1024 * 1024 * 1024,
            'T': 1000 * 1000 * 1000 * 1000,
            'TB': 1000 * 1000 * 1000 * 1000,
            'TIB': 1024 * 1024 * 1024 * 1024,
        }

        suffix = parts[2].upper()
        logger.debug('input suffix: %s', suffix)
        if suffix not in suffixes:
            msg = "Could not parse '{0}' [suffix] into usable byte size"
            raise RadulaError(msg.format(size))

        size = int(int(parts[1]) * suffixes.get(suffix))

    if bounds and size < minimum:
        logger.warn("Chunk size smaller than minimum. using default")
        size = default

    logger.debug("from_human_size parsed: %s bytes", size)
    if not size:
        logger.warn("Parsed chunk size was zero: %s", size)

    return size


def do_part_cksum(*args):
    """hash one chunk of a local file.
    Several parts are run simultaneously."""
    subject, n, chunk_size, key = args
    with open(subject, 'rb') as source_file:
        source_file.seek(chunk_size * n)
        hex_digest, b64_digest = key.compute_md5(source_file, size=chunk_size)
    return n, binascii.unhexlify(str(hex_digest))


def do_part_verify(source_key, dest_key, part_num,
                   chunk_start, chunk_size, total_parts):
    try:
        range_args = (chunk_start, (chunk_start + chunk_size - 1))
        range_query = "bytes=%d-%d" % range_args
        data = {}
        for which_key, key in [('source', source_key), ('dest', dest_key)]:
            logger.info("Verify Keys: Starting part %s of %s key" % (
                part_num + 1, which_key))
            d1 = time.time()
            resp = key.bucket.connection.make_request(
                "GET",
                bucket=key.bucket.name,
                key=key.name,
                headers={
                    'Range': range_query
                }
            )
            data[which_key] = resp.read()
            d2 = time.time() - d1
            fmt = "Verify Keys: Downloaded %s part %s in %0.2fs at %sps"
            logger.info(fmt % (
                which_key,
                part_num + 1,
                d2,
                human_size(len(data[which_key]) / d2)
                )
            )
        if data['source'] != data['dest']:
            fmt = "Verify keys: part %s does not match!"
            raise RadulaError(fmt % (part_num + 1))
    except KeyboardInterrupt:
        return ParallelSim.STOP
    except Exception as e:
        logger.exception(e)
        return ParallelSim.STOP


def do_part_upload(*args):
    """
    Upload a part of a MultiPartUpload

    Open the target file and read in a chunk. Since we can't pickle
    S3Connection or MultiPartUpload objects, we have to reconnect and lookup
    the MPU object with each part upload.
    """
    try:
        (s3, bucket_name, mpu, source_name, part_num, start,
         size, num_parts, is_copy, dest_conn, existing_part,
         generate_hashes) = args

        logger.debug("do_part_upload got args: %s" % (args,))

        if existing_part and check_skip_part(source_name, existing_part,
                                             start, size, is_copy):
            fmt = "MPU: %s, Part %d upload skipped."
            logging.info(fmt, mpu.id, part_num + 1)
            return True

        # Read the chunk from the file
        if is_copy:
            logger.info("Streaming Copy: starting  part %s" % (part_num + 1))
            range_query = "bytes=%d-%d" % (start, (start + size - 1))
            d1 = time.time()
            resp = s3.make_request(
                "GET",
                bucket=source_name[0],
                key=source_name[1],
                headers={
                    'Range': range_query
                }
            )
            data = resp.read()
            d2 = time.time() - d1
            fmt = "Streaming Copy: Downloaded part %s in %0.2fs at %sps"
            logger.info(fmt % (
                part_num + 1, d2, human_size(len(data) / d2)))
        else:
            data = _read_chunk(source_name, start, size)

        must_have(data, "Unexpectedly tried to read an empty chunk")

        if generate_hashes:
            h1 = time.time()
            fake_fp = StringIO(data)
            hex_digest, b64_digest = Key.compute_md5(Key(), fake_fp)
            fake_fp.close()
            part_hash = binascii.unhexlify(str(hex_digest))
            logger.debug("Finished part hash")
            h2 = time.time() - h1
            logger.info("Hashed part %s in %0.2fs at %sps" % (
                part_num + 1, h2, human_size(len(data) / h2)))
            del hex_digest, b64_digest, fake_fp

        def progress(x, y):
            logger.debug("Part %d: %0.2f%%" % (part_num + 1, 100. * x / y))

        try:
            # Do the upload
            t1 = time.time()
            mpu.upload_part_from_file(StringIO(data), part_num + 1,
                                      cb=progress)

            # Print some timings
            t2 = time.time() - t1
        except Exception:
            logger.error("Error while uploading. ", exc_info=True)
            raise

        s = len(data)
        logger.info("Uploaded part %s of %s (%s) in %0.2fs at %sps" % (
            part_num + 1, num_parts, human_size(s), t2, human_size(s / t2)))
        del data, mpu
    except KeyboardInterrupt:
        return ParallelSim.STOP
    except Exception as e:
        logger.exception(e)
        return ParallelSim.STOP

    if generate_hashes:
        return part_num, part_hash


def do_part_download(*args):
    """
    Download a part of an S3 object using Range header

    We utilize the existing S3 GET request implemented by Boto and tack on the
    Range header. We then read chunks of the file and write out to the
    correct position in the target file
    """
    try:
        (conn, key, target, part_num,
         chunk_start, chunk_size, num_parts) = args

        # Make the S3 request
        min_byte = chunk_start
        max_byte = chunk_start + chunk_size - 1

        resp = conn.make_request(
            "GET",
            bucket=key.bucket.name,
            key=key.name,
            headers={
                'Range': "bytes=%d-%d" % (min_byte, max_byte)
            })

        # Open the target file, seek to byte offset
        fd = os.open(target, os.O_WRONLY)
        fmt = "Opening file descriptor %d, seeking to %d"
        logger.debug(fmt % (fd, min_byte))
        os.lseek(fd, min_byte, os.SEEK_SET)

        fmt = "Reading HTTP stream in %dM chunks"
        logger.debug(fmt % (chunk_size/1024./1024))
        t1 = time.time()
        download_size = 0
        while True:
            data = resp.read(_mb)
            if data == "":
                break
            os.write(fd, data)
            download_size += len(data)
        t2 = time.time() - t1
        os.close(fd)
        print_timings(download_size, t2, "downloading")
    except KeyboardInterrupt:
        return ParallelSim.STOP
    except Exception as e:
        logger.exception(e)
        raise


def do_part_rehash(*args):
    """
    Download a part of an S3 object using Range header
    for purposes for computing a hash; not storage.
    """
    try:
        (conn, key, part_num,
         chunk_start, chunk_size, num_parts) = args

        # Make the S3 request
        min_byte = chunk_start
        max_byte = chunk_start + chunk_size - 1

        resp = conn.make_request(
            "GET",
            bucket=key.bucket.name,
            key=key.name,
            headers={
                'Range': "bytes=%d-%d" % (min_byte, max_byte)
            })

        fmt = "Reading HTTP stream in %dM chunks"
        logger.debug(fmt % (chunk_size/1024./1024))
        t1 = time.time()
        download_size = 0
        buffer = ""
        while True:
            data = resp.read(_mb)
            if data == "":
                break
            buffer += data
            download_size += len(data)

        buffer = StringIO(buffer)
        hex_digest, b64_digest = Key.compute_md5(Key(), buffer)
        buffer.close()
        part_hash = binascii.unhexlify(str(hex_digest))

        t2 = time.time() - t1
        print_timings(download_size, t2, "downloading")

        logger.debug("download size: %s", download_size)

        return part_num, part_hash
    except KeyboardInterrupt:
        return ParallelSim.STOP
    except Exception as e:
        logger.exception(e)
        raise


def do_mp_acl_set(*args):
    rad, change_type, kwargs = args
    changes = {
        RadulaACLChange.ALLOW: rad.allow_user,
        RadulaACLChange.DISALLOW: rad.disallow_user,
    }

    method = changes.get(change_type, None)
    must_have(method, "ACL Change type not recognized")

    return method(**kwargs)


def _read_chunk(source_name, start, size):
    fp = open(source_name, 'rb')
    fp.seek(start)
    data = fp.read(size)
    fp.close()
    return data


def config_check():
    env_boto_config = os.environ.get("BOTO_CONFIG", None)
    boto_configs = [
        env_boto_config,
        os.path.expanduser("~/.boto"),
        os.path.expanduser("~/.aws/credentials")
    ]

    if env_boto_config and not os.path.exists(env_boto_config):
        message = "Environment variable BOTO_CONFIG is set to '{0}', " \
                  "but file not found"
        message = message.format(env_boto_config)
        print_warning(message)

    for config in boto_configs:
        if not config or not os.path.exists(config):
            continue
        mode = os.stat(config).st_mode
        if mode & 0o77:
            message = 'Boto config file "{0}" is mode {1}. Recommend ' \
                      'changing to 0600 to avoid exposing credentials'
            message = message.format(config, oct(mode & 0o777))
            print_warning(message)

        if not os.access(config, os.R_OK):
            message = 'Config file {0} exists, but it is not readable.'
            message = message.format(config)
            print_warning(message)


def file_size(src):
    """quick file sizing"""
    src.seek(0, 2)
    return src.tell()


def print_timings(source_size, timing, verb):
    args = (verb, human_size(source_size),
            timing, human_size(source_size / timing))
    logger.info("Finished %s %s in %0.2fs (%sps)" % args)


def print_url(key):
    logger.info("Download URL: {url}".format(url=url_for(key)))


def calculate_num_chunks(source_size, chunk_size):
    num_parts = int(max(1, ceil(float(source_size) / float(chunk_size))))
    return num_parts, chunk_size


def calculate_chunks(source_size, chunk_size=Radula.DEFAULT_CHUNK):
    """generate a chunk count and size for a large file."""
    if int(source_size) < int(chunk_size):
        return 1, source_size

    chunk_count = int(ceil(source_size / float(chunk_size)))
    return chunk_count, chunk_size


def legacy_calculate_chunks(source_size):
    """generate a chunk count and size for a large file.
    strategy used by radula <0.6.0, kept for compatibility reasons"""
    default_chunk = 100 * _mib
    if source_size < default_chunk:
        return 1, source_size

    split_count = 50
    chunk_size = max(default_chunk,
                     int(ceil(source_size / float(split_count))))
    chunk_size = min(_gib, chunk_size)
    chunk_count = int(ceil(source_size / float(chunk_size)))

    return chunk_count, chunk_size


def url_for(key):
    """proxy generate_url in boto.Key"""
    return re.sub("\?.+$", "",
                  key.generate_url(expires_in=0, query_auth=False))


def guess_target_name(source_path, target_key):
    key_name = target_key
    basename = os.path.basename(source_path)
    if not key_name:
        key_name = basename
    elif key_name[-1] == "/":
        key_name = "".join([key_name, basename])
    return key_name


def print_warning(message):
    print '!' * 48
    print '! WARNING'
    print '! ' + message
    print '!' * 48


def get_mpu_by_id(bucket, mpu_id):
    for mp in bucket.list_multipart_uploads():
        if mp.id == mpu_id:
            return mp
    raise Exception("Could not find MultiPartUpload %s" % mpu_id)


def check_skip_part(source_name, existing_part, start, size, is_copy):
    skip_part = False
    if is_copy:
        skip_part = True
    elif existing_part:
        logging.debug("Part ETAG: %s", existing_part)
        data = _read_chunk(source_name, start, size)
        hash_obj = md5()
        hash_obj.update(data)
        hex_digest = hash_obj.hexdigest()
        logging.debug("calculated digest of local part: %s",
                      hex_digest)
        if existing_part == hex_digest:
            skip_part = True

    logging.debug("skip part: %s", skip_part)
    return skip_part


def must_have(value, message, *args):
    if not value:
        raise RadulaError(message.format(*args))


def dry_run_msg(func, *args):
    fmt = 'DRY RUN: {0}-> {1}'
    print fmt.format(func, ", ".join(args))
    return None


def to_timestamp(dt):
    epoch = datetime(1970, 1, 1).replace(tzinfo=None)
    return int((dt - epoch).total_seconds())
