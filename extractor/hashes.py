import hashlib
from .base import BaseExtractor


class Hashes(BaseExtractor):
    def __init__(self, data):
        self.data = data

    def extract(self, sample):
        sample.hash_md5 = hashlib.md5(self.data).hexdigest()
        sample.hash_sha1 = hashlib.sha1(self.data).hexdigest()
        sample.hash_sha256 = hashlib.sha256(self.data).hexdigest()
