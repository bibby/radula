from rad import RadulaLib, RadulaError


class RadulaProxy(object):

    def __init__(self, profile=None):
        self.lib = RadulaLib()
        self.lib.connect(profile)

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

        self.lib.upload_threads = int(kwargs.get("threads"))
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
        """removes a remote subject key"""
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Missing file(s) to remove")

        self.lib.remove_key(subject)

    def keys(self, **kwargs):
        """lists keys of a subject bucket"""
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Missing bucket to list")

        for key in sorted(self.lib.keys(subject)):
            print key

    def info(self, **kwargs):
        """prints metadata for a remote subject key"""
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Missing remote subject key to get info for")

        print self.lib.info(subject)

    def local_md5(self, **kwargs):
        """performs a multithreaded hash of a local subject file"""
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Missing local subject file")

        self.lib.thread_count = int(kwargs.get("threads"))
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
        print self.lib.multipart_list(subject)

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
        print self.lib.multipart_clean(subject)
