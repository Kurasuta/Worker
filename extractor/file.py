from lib.regex import entropy
from lib.performance import SubTimer
from .base import BaseExtractor
from datetime import datetime
import hashlib
import ssdeep
from magic import magic


class File(BaseExtractor):
    def __init__(self, data, pe, peyd, timer):
        self.data = data
        self.pe = pe
        self.peyd = peyd
        self.timer = timer

    def extract(self, sample):
        timer = SubTimer(self.timer)

        timer.mark('hash')
        sample.hash_md5 = hashlib.md5(self.data).hexdigest()
        sample.hash_sha1 = hashlib.sha1(self.data).hexdigest()
        sample.hash_sha256 = hashlib.sha256(self.data).hexdigest()
        sample.ssdeep = ssdeep.hash(self.data)

        timer.mark('meta')
        sample.magic = magic.from_buffer(self.data[:1024])
        sample.size = len(self.data)
        sample.entropy = entropy(self.data)
        sample.entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        sample.first_kb = [c for c in self.data[:1024]]
        if hasattr(self.pe, 'FILE_HEADER'):
            sample.build_timestamp = datetime.utcfromtimestamp(self.pe.FILE_HEADER.TimeDateStamp)

        if self.peyd:
            timer.mark('peyd')
            sample.peyd = [m for m in self.peyd.all_matches(self.pe)]
