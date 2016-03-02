from rad import RadulaLib, RadulaError, from_human_size, Radula
from boto.compat import json


class RadulaProxy(object):

    def __init__(self, profile=None, connection=None):
        self.lib = RadulaLib()
        self.lib.connect(profile, connection)

    def mb(self, **kwargs):
        """alias of make_bucket"""
        return self.make_bucket(**kwargs)

    def make_bucket(self, **kwargs):
        """proxy make_bucket to boto"""
        bucket = kwargs.get("subject", None)
        if not bucket:
            raise RadulaError("Bucket name empty")

        if self.lib.make_bucket(bucket):
            print "Created bucket: {0}".format(bucket)

    def rb(self, **kwargs):
        """alias of remove_bucket"""
        return self.remove_bucket(**kwargs)

    def remove_bucket(self, **kwargs):
        """proxy remove_bucket to boto"""
        bucket = kwargs.get("subject", None)
        if not bucket:
            raise RadulaError("Bucket name empty")
        if self.lib.remove_bucket(bucket):
            print "Removed bucket {0}".format(bucket)

    def lb(self, **kwargs):
        """alias of list_buckets"""
        self.list_buckets(**kwargs)

    def list_buckets(self, **kwargs):
        """proxy list_buckets to boto"""
        for bucket_name in sorted([bucket.name for bucket in self.lib.get_buckets()]):
            print bucket_name

    def put(self, **kwargs):
        """alias of upload"""
        return self.upload(**kwargs)

    def up(self, **kwargs):
        """alias of upload"""
        return self.upload(**kwargs)

    def upload(self, **kwargs):
        """initiate a multipart upload. See README for complete usage"""
        subject = kwargs.get("subject", None)
        target = kwargs.get("target", None)
        if not subject:
            raise RadulaError("Missing file(s) to upload")
        if not target:
            raise RadulaError("Missing bucket/key target")

        self.lib.thread_count = int(kwargs.get("threads"))
        chunk_size = kwargs.get("chunk_size", None)
        if chunk_size:
            self.lib.chunk_size = from_human_size(chunk_size, minimum=RadulaLib.MIN_CHUNK)
        self.lib.upload(subject, target, verify=kwargs.get("verify", False))

    def get(self, **kwargs):
        """alias of download"""
        return self.download(**kwargs)

    def dl(self, **kwargs):
        """alias of download"""
        return self.download(**kwargs)

    def download(self, **kwargs):
        """download remote subject to a local target file"""
        subject = kwargs.get("subject", None)
        target = kwargs.get("target", None)
        if not subject:
            raise RadulaError("Missing file(s) to download")

        self.lib.download(subject, target, force=kwargs.get("force", False))

    def rm(self, **kwargs):
        """alias of remove"""
        return self.remove(**kwargs)

    def remove(self, **kwargs):
        """removes remote subject keys, any passed over the cli"""
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Missing file(s) to remove")

        target = kwargs.get("target", None)
        remainder = kwargs.get("remainder", [])
        subject_keys = [k for k in [subject] + [target] + remainder if k]
        dry_run = kwargs.get("dry_run", False)

        for subject in subject_keys:
            for key in self.lib.remove_key(subject, dry_run=dry_run):
                print key

    def keys(self, **kwargs):
        """lists keys of a subject bucket"""
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Missing bucket to list")

        for key in sorted(self.lib.keys(subject, long_keys=kwargs.get("long_key"))):
            print key

    def info(self, **kwargs):
        """prints metadata for a remote subject key"""
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Missing remote subject key to get info for")

        target = kwargs.get("target", None)
        remainder = kwargs.get("remainder", [])

        subject_keys = [k for k in [subject] + [target] + remainder if k]
        actual_keys = []
        info = []
        for subject_key in subject_keys:
            bucket_name, pattern = Radula.split_bucket(subject_key)
            if not pattern:  # is not a key, but a bucket
                info.append({
                    "bucket": subject_key,
                    "info": self.lib.info(subject_key)
                })
            else:
                l = len(actual_keys)
                for key in self.lib.keys(subject_key, long_keys=True):
                    actual_keys.append(key)
                if len(actual_keys) == l:
                    raise RadulaError("Key not found: {0}".format(subject_key))

        for subject_key in actual_keys:
            info.append({
                "key": subject_key,
                "info": self.lib.info(subject_key)
            })

        print json.dumps(info).replace('\\"', '')

    def local_md5(self, **kwargs):
        """performs a multithreaded hash of a local subject file"""
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Missing local subject file")

        self.lib.thread_count = int(kwargs.get("threads"))
        chunk_size = kwargs.get("chunk_size", None)
        if chunk_size:
            self.lib.chunk_size = from_human_size(chunk_size, minimum=RadulaLib.MIN_CHUNK)
        print self.lib.local_md5(subject)

    def remote_md5(self, **kwargs):
        """fetches hash from metadata of a remote subject"""
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Missing remote subject key")

        print self.lib.remote_md5(subject)

    def verify(self, **kwargs):
        """compares hashes of a local subject and a remote target"""
        subject = kwargs.get("subject", None)
        target = kwargs.get("target", None)
        if not subject:
            raise RadulaError("Missing local subject to compare")
        if not target:
            raise RadulaError("Missing remote target to compare")

        self.lib.thread_count = int(kwargs.get("threads"))
        chunk_size = kwargs.get("chunk_size", None)
        if chunk_size:
            self.lib.chunk_size = from_human_size(chunk_size, minimum=RadulaLib.MIN_CHUNK)
        if not self.lib.verify(subject, target):
            exit(1)

    def mpl(self, **kwargs):
        """alias of multipart_list"""
        return self.multipart_list(**kwargs)

    def mp_list(self, **kwargs):
        """alias of multipart_list"""
        return self.multipart_list(**kwargs)

    def multipart_list(self, **kwargs):
        """lists lingering multipart upload parts """
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Missing remote subject bucket or key to list")
        bucket, uploads = self.lib.multipart_list(subject)
        lines = []
        for up in uploads:
            lines.append("\t".join((up.bucket.name, up.key_name, up.id, up.initiator.display_name, up.initiated)))

        print "\n".join(lines)

    def mpc(self, **kwargs):
        """alias of multipart_clean"""
        return self.multipart_clean(**kwargs)

    def mp_clean(self, **kwargs):
        """alias of multipart_clean"""
        return self.multipart_clean(**kwargs)

    def multipart_clean(self, **kwargs):
        """removes lingering multipart upload parts for a remote bucket or key"""
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Missing remote subject bucket or key to clean")
        if self.lib.multipart_clean(subject):
            print "Lingering parts removed."

    def sc(self, **kwargs):
        """alias of streaming-copy"""
        return self.streaming_copy(**kwargs)

    def streaming_copy(self, **kwargs):
        """copy from one endpoint to another without touching a disk"""
        source = kwargs.get("subject", None)
        dest = kwargs.get("target", None)
        dest_profile = kwargs.get("destination", None)
        force = kwargs.get("force", None)
        verify = kwargs.get("verify", False)
        if not source:
            raise RadulaError("missing source bucket/key")
        if not dest:
            raise RadulaError("missing destination bucket/key")

        chunk_size = kwargs.get("chunk_size", None)
        if chunk_size:
            self.lib.chunk_size = from_human_size(chunk_size, minimum=RadulaLib.MIN_CHUNK)

        self.lib.streaming_copy(source, dest, dest_profile, force, verify)

    def cat(self, **kwargs):
        source = kwargs.get("subject", None)
        if not source:
            raise RadulaError("missing source bucket/key")
        self.lib.cat(source)