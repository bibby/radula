from rad import RadulaLib, RadulaError


class RadulaProxy(object):

    def __init__(self):
        self.lib = RadulaLib()
        self.lib.connect()

    def mb(self, **kwargs):
        return self.make_bucket(**kwargs)

    def make_bucket(self, **kwargs):
        bucket = kwargs.get("subject", None)
        if not bucket:
            raise RadulaError("Bucket name empty")

        if self.lib.make_bucket(bucket):
            print "Created bucket: {0}".format(bucket)

    def rb(self, **kwargs):
        return self.remove_bucket(**kwargs)

    def remove_bucket(self, **kwargs):
        bucket = kwargs.get("subject", None)
        if not bucket:
            raise RadulaError("Bucket name empty")
        if self.lib.remove_bucket(bucket):
            print "Removed bucket {0}".format(bucket)

    def lb(self, **kwargs):
        self.list_buckets(**kwargs)

    def list_buckets(self, **kwargs):
        for bucket_name in sorted([bucket.name for bucket in self.lib.get_buckets()]):
            print bucket_name

    def put(self, **kwargs):
        return self.upload(**kwargs)

    def up(self, **kwargs):
        return self.upload(**kwargs)

    def upload(self, **kwargs):
        subject = kwargs.get("subject", None)
        target = kwargs.get("target", None)
        if not subject:
            raise RadulaError("Missing file(s) to upload")
        if not target:
            raise RadulaError("Missing bucket/key target")

        self.lib.upload_threads = int(kwargs.get("threads"))
        self.lib.upload(subject, target)

    def get(self, **kwargs):
        return self.download(**kwargs)

    def dl(self, **kwargs):
        return self.download(**kwargs)

    def download(self, **kwargs):
        subject = kwargs.get("subject", None)
        target = kwargs.get("target", None)
        if not subject:
            raise RadulaError("Missing file(s) to upload")

        self.lib.download(subject, target)

    def rm(self, **kwargs):
        return self.remove(**kwargs)

    def remove(self, **kwargs):
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Missing file(s) to upload")

        self.lib.remove_key(subject)

    def keys(self, **kwargs):
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Missing bucket to list")

        for key in sorted(self.lib.keys(subject)):
            print key

    def info(self, **kwargs):
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Missing subject file")

        print self.lib.info(subject)

    def local_md5(self, **kwargs):
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Missing subject file")

        print self.lib.local_md5(subject)

    def remote_md5(self, **kwargs):
        subject = kwargs.get("subject", None)
        if not subject:
            raise RadulaError("Missing subject file")

        print self.lib.remote_md5(subject)

    def verify(self, **kwargs):
        subject = kwargs.get("subject", None)
        target = kwargs.get("target", None)
        if not subject:
            raise RadulaError("Missing local subject to compare")
        if not target:
            raise RadulaError("Missing remote target to compare")

        if not self.lib.verify(subject, target):
            exit(1)
