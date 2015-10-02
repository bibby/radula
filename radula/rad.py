import os
import sys
import fnmatch
import time
import logging
import binascii
from hashlib import md5
from glob import glob
from multiprocessing import Pool
import boto
import boto.s3.connection
from boto.s3.bucket import Bucket
from boto.s3.key import Key
from math import ceil
from cStringIO import StringIO
logger = logging.getLogger("radula")
logger.setLevel(logging.INFO)


class RadulaError(Exception):
    pass


class RadulaClient(object):
    DEFAULT_UPLOAD_THREADS = 10

    def __init__(self):
        self.conn = None
        self.profile = None
        self.thread_count = RadulaClient.DEFAULT_UPLOAD_THREADS

    def connect(self, profile=None):
        """create or reuse a boto s3 connection.
        An option aws profile may be given.
        """
        if profile:
            self.profile = profile

        if self.profile:
            os.environ["AWS_PROFILE"] = self.profile

        if not self.conn:
            self.conn = self.new_connection()
        return self.conn

    def new_connection(self):
        """create a fresh boto s3 connection"""
        return boto.connect_s3(calling_format=boto.s3.connection.OrdinaryCallingFormat())


class Radula(RadulaClient):
    BUCKET = "bucket"
    KEY = "key"

    @staticmethod
    def split_bucket(subject):
        """separate the bucket and key components from
        a string, such as mybucket/path/to/key.
        boto objects may also be given, and they already
        know their constituent pieces.
        """
        if isinstance(subject, Bucket):
            return subject, None
        if isinstance(subject, Key):
            return subject.bucket, subject

        s = subject.split('/', 1)
        if len(s) == 1:
            s.append(None)

        return tuple(s)

    def get_acl(self, **kwargs):
        """fetch a description of the ACL policy
        on a subject bucket or key"""
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Subject (bucket/key) is needed")

        bucket, key = self.split_bucket(subject)
        bucket = self.conn.get_bucket(bucket)

        if key:
            subject_type = Radula.KEY
            subject = bucket.get_key(key)
        else:
            subject = bucket
            subject_type = Radula.BUCKET

        policy = subject.get_acl()
        grants = self.format_policy(policy)
        print "ACL for {0}: {1}".format(subject_type, subject)
        print grants

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
            grants.append("[{0}] {1} = {2}".format(grant_type, u, g.permission))

        return "\n".join(sorted(grants))

    def compare_acl(self, **kwargs):
        """
        Compares bucket ACL to those of its keys, with a small report
        listing divergent policies
        """
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Subject (bucket/key) is needed")

        bucket, key = self.split_bucket(subject)
        bucket = self.conn.get_bucket(bucket)

        if key:
            keys = [bucket.get_key(key)]
        else:
            keys = bucket.list()

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
        if not subject:
            raise RadulaError("Subject (bucket/key) is needed")

        bucket, key = self.split_bucket(subject)
        bucket = self.conn.get_bucket(bucket)
        policy = bucket.get_acl()
        bucket_acl = self.format_policy(policy)

        print "Bucket ACL for: {0}".format(bucket.name)
        print bucket_acl
        print "---------\n"

        if key:
            keys = [bucket.get_key(key)]
        else:
            keys = bucket.list()

        for key in keys:
            print "Setting bucket's ACL on {0}".format(key.name)
            key.set_acl(policy)

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
        target = kwargs.get("target", None)
        if not user:
            raise RadulaError("User is required during permission grants")
        if not target:
            raise RadulaError("A bucket or key is required during permission grants")

        read = kwargs.get("acl_read", None)
        write = kwargs.get("acl_write", None)
        if not any([read, write]):
            read = True

        bucket, key = self.split_bucket(target)
        target = self.conn.get_bucket(bucket)
        target_type = Radula.BUCKET

        if key:
            target = target.get_key(key)
            target_type = Radula.KEY

        permissions = []
        if read:
            permissions.append("READ")
        if write:
            permissions.append("WRITE")

        policy = target.get_acl()
        acl = policy.acl

        for permission in permissions:
            if self.is_granted(acl.grants, user, permission):
                print "User {0} already has {1} for {2} {3}, skipping".format(
                    user, permission, target_type, target.name
                )
                continue
            print "granting {0} to {1} on {2} {3}".format(permission, user, target_type, target.name)
            acl.add_user_grant(permission, user)

        target.set_acl(policy)

        if target_type == Radula.BUCKET:
            kwargs_copy = kwargs.copy()
            for key in target:
                kwargs_copy.update({"target": key})
                self.allow_user(**kwargs_copy)

    def disallow(self, **kwargs):
        """alias of disallow_user"""
        self.disallow_user(**kwargs)

    def disallow_user(self, **kwargs):
        """
        Will remove a grant from a user for a bucket or key.
        If neither read or write are specified, BOTH are assumed.
        """
        user = kwargs.get("subject", None)
        target = kwargs.get("target", None)
        if not user:
            raise RadulaError("User is required during permission grants")
        if not target:
            raise RadulaError("A bucket or key is required during permission grants")

        permissions = []
        if kwargs.get("acl_read", None):
            permissions.append("READ")
        if kwargs.get("acl_write", None):
            permissions.append("WRITE")
        if not len(permissions):
            permissions = ['READ', 'WRITE', 'READ_ACP', 'WRITE_ACP', 'FULL_CONTROL']

        bucket, key = self.split_bucket(target)
        target = self.conn.get_bucket(bucket)
        target_type = Radula.BUCKET

        if key:
            target = target.get_key(key)
            target_type = Radula.KEY
        else:
            kwargs_copy = kwargs.copy()
            for key in target:
                kwargs_copy.update({"target": key})
                self.disallow_user(**kwargs_copy)

        policy = target.get_acl()
        acl = policy.acl

        grant_count = len(acl.grants)
        acl.grants = [g for g in acl.grants if self.grant_filter(g, user, permissions, policy.owner.id, target)]
        if len(acl.grants) != grant_count:
            target.set_acl(policy)
        else:
            print "No change for {0} {1}".format(target_type, target.name)

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
    def grant_filter(grant, user, permissions, owner, subject):
        """
        Grant filter function, returning True for items that should be kept.
        Grants for the policy owner are kept.
        Only grants matching the user and permissions we wish to eliminate are tossed (False).
        """
        # don't restrict the owner; suspend them instead (but not here)
        if user and user == owner:
            return True
        if grant.id != user:
            return True
        if grant.permission in permissions:
            print "Grant dropped: user={0}, permission={1} on {2}".format(grant.id, grant.permission, subject)
            return False
        return True


class RadulaLib(RadulaClient):
    PROGRESS_CHUNKS = 20

    def make_bucket(self, bucket):
        """proxy make_bucket in boto"""
        for existing_bucket in self.conn.get_all_buckets():
            if bucket == existing_bucket.name:
                print "Bucket {0} already exists.".format(bucket)
                return False

        return self.conn.create_bucket(bucket)

    def remove_bucket(self, bucket):
        """proxy delete_bucket in boto"""
        return self.conn.delete_bucket(bucket)

    def get_buckets(self):
        """proxy get_all_buckets in boto"""
        return self.conn.get_all_buckets()

    def remove_key(self, subject):
        """proxy delete_key in boto"""
        bucket, key = Radula.split_bucket(subject)
        self.conn.get_bucket(bucket).delete_key(key)

    def upload(self, subject, target, verify=False):
        """initiate multipart uploads of potential plural local subject files"""
        bucket_name, target_key = Radula.split_bucket(target)
        bucket = self.conn.get_bucket(bucket_name)
        files = glob(subject)
        file_count = len(files)
        if file_count == 0:
            raise RadulaError("No file(s) to upload: used {0}".format(subject))

        for source_path in files:
            key_name = target_key
            basename = os.path.basename(source_path)
            if not key_name:
                key_name = basename
            elif key_name[-1] == "/":
                key_name = "".join([key_name, basename])

            if not self._start_upload(source_path, bucket, key_name, verify):
                raise RadulaError("{0} did not correctly upload".format(source_path))

    def _file_size(self, src):
        """quick file sizing"""
        src.seek(0, 2)
        return src.tell()

    def _chunk(self, source_size):
        """generate a chunk count and size for a large file.
        tiny_size is also calculated for last-part folding"""
        _mb = 1024 * 1024
        _gb = _mb * 1024
        tiny_size = 25 * _mb
        default_chunk = 100 * _mb

        if source_size < tiny_size:
            return 1, source_size, tiny_size

        split_count = 50
        chunk_size = max(default_chunk, int(ceil(source_size / float(split_count))))
        chunk_size = min(_gb, chunk_size)
        chunk_count = int(ceil(source_size / float(chunk_size)))

        return chunk_count, chunk_size, tiny_size

    def url_for(self, key):
        """proxy generate_url in boto.Key"""
        return key.generate_url(expires_in=0, query_auth=False)

    def _start_upload(self, source_path, bucket, key_name, verify=False):
        """multipart upload strategy.
        Borrowed heavily from the work of David Arthur
        https://github.com/mumrah/s3-multipart
        """
        max_tries = 5
        src = open(source_path, 'rb')
        source_size = self._file_size(src)

        num_parts, chunk_size, tiny_size = self._chunk(source_size)

        if num_parts == 1:
            src.seek(0)
            t1 = time.time()
            k = bucket.new_key(key_name)
            k.set_contents_from_file(src)
            t2 = time.time() - t1
            s = source_size/1024./1024.
            logger.info("Finished uploading %0.2fM in %0.2fs (%0.2fMBps)" % (s, t2, s/t2))
            logger.info("Download URL: {url}".format(url=self.url_for(k)))
            return self.verify(source_path, k)

        mpu = bucket.initiate_multipart_upload(key_name)
        logger.info("Initialized upload: %s" % mpu.id)

        # Generate arguments for invocations of do_part_upload
        def gen_args(num, fold_last_chunk):
            for i in range(num):
                chunk_start = chunk_size * i
                s3 = self.new_connection()
                args = [s3, bucket.name, mpu.id, src.name, i, chunk_start, chunk_size, max_tries, 0, num]
                if i == (num-1) and fold_last_chunk is True:
                    args[6] = chunk_size * 2
                yield tuple(args)

        # If the last part is small, just fold it into the previous part
        fold_last = ((source_size % chunk_size) < tiny_size)

        pool = None
        try:
            # Create a pool of workers
            pool = Pool(processes=self.thread_count)
            t1 = time.time()
            pool.map_async(do_part_upload, gen_args(num_parts, fold_last)).get(9999999)
            # Print out some timings
            t2 = time.time() - t1
            s = source_size/1024./1024.
            # Finalize
            src.close()
            mpu.complete_upload()
            key = bucket.get_key(key_name)
            key.set_acl(bucket.get_acl())
            logger.info("Finished uploading %0.2fM in %0.2fs (%0.2fMBps)" % (s, t2, s/t2))
            logger.info("Download URL: {url}".format(url=self.url_for(key)))

            if not verify:
                return True

            # Verify upload
            return self.verify(source_path, key)
        except KeyboardInterrupt:
            logger.warn("Received KeyboardInterrupt, canceling upload")
            try:
                if pool:
                    pool.terminate()
                mpu.cancel_upload()
            except:
                logger.error("Error while cancelling upload")
                logger.error()
            raise
        except:
            exc_class, exc, tb = sys.exc_info()
            logger.error("Encountered an error, canceling upload")
            logger.error(exc)
            try:
                if pool:
                    pool.terminate()
                mpu.cancel_upload()
            except:
                logger.error("Error while cancelling upload")
            raise

    def download(self, subject, target, force=False):
        """proxy download in boto, warning user about overwrites"""
        basename = os.path.basename(subject)
        if not target:
            target = basename

        if os.path.isdir(target):
            target = "/".join([target, basename])

        if os.path.isfile(target) and not force:
            msg = "File {0} exists already. Overwrite? [yN]: ".format(target)
            if not raw_input(msg).lower() == 'y':
                print "Aborting download."
                exit(0)

        bucket, key = Radula.split_bucket(subject)
        if not key:
            raise RadulaError("Missing key to download")
        print "bucket", bucket, "key", key
        boto_key = self.conn.get_bucket(bucket).get_key(key)
        if not boto_key:
            raise RadulaError("Key not found: {0}".format(key))

        def progress_callback(a, b):
            percentage = 0
            if a:
                percentage = 100 * (float(a)/float(b))
            print "Download Progress: %.2f%%" % percentage

        boto_key.get_contents_to_filename(target, cb=progress_callback, num_cb=self.PROGRESS_CHUNKS)

    def keys(self, subject):
        """list keys in a bucket with consideration of glob patterns if provided"""
        bucket_name, pattern = Radula.split_bucket(subject)

        bucket = self.conn.get_bucket(bucket_name)
        if not pattern:
            return [key.name for key in bucket]

        def key_buffer(buck, buffer_size=256):
            buffer_keys = []
            for k in buck:
                buffer_keys.append(k.name)
                if len(buffer_keys) >= buffer_size:
                    filtered_keys = fnmatch.filter(buffer_keys, pattern)
                    if len(filtered_keys):
                        yield filtered_keys
                    buffer_keys = []
            yield fnmatch.filter(buffer_keys, pattern)

        keys = []
        for matching_keys in key_buffer(bucket):
            keys += matching_keys
        return keys

    def info(self, subject):
        """fetch metadata of a remote subject key"""
        bucket_name, key_name = Radula.split_bucket(subject)
        bucket = self.conn.get_bucket(bucket_name)
        key = bucket.get_key(key_name)
        return key.__dict__

    def remote_md5(self, subject):
        """fetch hash from metadata of a remote subject key"""
        bucket_name, key_name = Radula.split_bucket(subject)
        bucket = self.conn.get_bucket(bucket_name)
        key = bucket.get_key(key_name)
        return key.etag.translate(None, '"')

    def local_md5(self, subject):
        """performs a multithreaded hash of a local subject file"""
        if not os.path.isfile(subject):
            raise RadulaError("Local file '{0}' not found".format(subject))
        hash_obj = md5()

        with open(subject, 'rb') as source_file:
            source_size = self._file_size(source_file)
            num_parts, chunk_size, tiny_size = self._chunk(source_size)
            key = Key()

            if num_parts == 1:
                source_file.seek(0)
                hash_obj.update(source_file.read(source_size))
            else:
                def gen_args(num):
                    for n in xrange(num):
                        yield (subject, n, chunk_size, key)

                pool = Pool(processes=self.thread_count)
                t1 = time.time()
                parts = pool.map_async(do_part_cksum, gen_args(num_parts)).get(9999999)
                # Print out some timings
                t2 = time.time() - t1

                s = source_size/1024./1024.
                logger.info("Finished hashing %0.2fM in %0.2fs (%0.2fMBps)" % (s, t2, s/t2))
                hash_obj.update(''.join(parts))

        hex_digest = hash_obj.hexdigest()
        if num_parts == 1:
            return hex_digest
        return '{0}-{1}'.format(hex_digest, num_parts)

    def verify(self, subject, target):
        """compares hashes of a local subject and a remote target"""
        local_md5 = self.local_md5(subject)
        remote_md5 = self.remote_md5(target)

        if local_md5 == remote_md5:
            logging.info("Checksum Verified!")
            logging.info("Local and remote targets @ {0}".format(local_md5))
            return True
        else:
            logging.error("LocalMD5: {0} ; RemoteMD5: {1}".format(local_md5, remote_md5))
            print >> sys.stderr, "DIFFERENT CKSUMS!\nLocal {0}\nRemote {1}".format(local_md5, remote_md5)
            return False

    def multipart_list(self, subject, return_list=False):
        """lists lingering multipart upload parts """
        bucket_name, key_name = Radula.split_bucket(subject)
        bucket = self.conn.get_bucket(bucket_name)

        lines = []
        uploads = bucket.list_multipart_uploads()
        if key_name:
            uploads = [up for up in uploads if up.key_name == key_name]

        if return_list:
            return bucket, uploads

        for up in uploads:
            lines.append("\t".join((up.bucket.name, up.key_name, up.id, up.initiator.display_name, up.initiated)))

        return "\n".join(lines)

    def multipart_clean(self, subject):
        """alias of multipart_clean"""
        bucket, uploads = self.multipart_list(subject, return_list=True)
        for up in uploads:
            logging.info("Canceling {0} {1}".format(up.key_name, up.id))
            bucket.cancel_multipart_upload(up.key_name, up.id)
        return True


def do_part_cksum(args):
    """hash one chunk of a local file.
    Several parts are run simultaneously."""
    subject, n, chunk_size, key = args
    with open(subject, 'rb') as source_file:
        source_file.seek(chunk_size * n)
        hex_digest, b64_digest = key.compute_md5(source_file, size=chunk_size)
    return binascii.unhexlify(str(hex_digest))


def do_part_upload(args):
    """
    Upload a part of a MultiPartUpload

    Open the target file and read in a chunk. Since we can't pickle
    S3Connection or MultiPartUpload objects, we have to reconnect and lookup
    the MPU object with each part upload.

    :type args: tuple of (string, string, string, int, int, int)
    :param args: The actual arguments of this method. Due to lameness of
                 multiprocessing, we have to extract these outside of the
                 function definition.

                 The arguments are: S3 Bucket name, MultiPartUpload id, file
                 name, the part number, part offset, part size
    """
    s3, bucket_name, mpu_id, filename, i, start, size, max_tries, current_tries, num_parts = args
    logger.debug("do_part_upload got args: %s" % (args,))

    bucket = s3.lookup(bucket_name)
    mpu = None
    for mp in bucket.list_multipart_uploads():
        if mp.id == mpu_id:
            mpu = mp
            break
    if mpu is None:
        raise Exception("Could not find MultiPartUpload %s" % mpu_id)

    # Read the chunk from the file
    fp = open(filename, 'rb')
    fp.seek(start)
    data = fp.read(size)
    fp.close()
    if not data:
        raise Exception("Unexpectedly tried to read an empty chunk")

    def progress(x, y):
        logger.debug("Part %d: %0.2f%%" % (i+1, 100.*x/y))

    try:
        # Do the upload
        t1 = time.time()
        mpu.upload_part_from_file(StringIO(data), i+1, cb=progress)

        # Print some timings
        t2 = time.time() - t1
        s = len(data)/1024./1024.
        logger.info("Uploaded part %s of %s (%0.2fM) in %0.2fs at %0.2fMBps" % (i+1, num_parts, s, t2, s/t2))
    except:
        exc_class, exc, tb = sys.exc_info()
        logger.debug("Retry request %d of max %d times" % (current_tries, max_tries))
        if current_tries > max_tries:
            logger.error(exc)
            raise exc
        else:
            current_tries += 1
            logger.warn("Error while uploading. Attempting retry #{0} of {1}".format(current_tries, max_tries))
            time.sleep(3)
            do_part_upload((s3, bucket_name, mpu_id, filename, i, start, size, max_tries, current_tries, num_parts))
