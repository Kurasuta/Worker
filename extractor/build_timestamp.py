from datetime import datetime
from .base import BaseExtractor


class BuildTimestamp(BaseExtractor):
    def __init__(self, data, pe):
        self.data = data
        self.pe = pe

    def extract(self, sample):
        if not hasattr(self.pe, 'FILE_HEADER'):
            return
        sample.build_timestamp = datetime.utcfromtimestamp(self.pe.FILE_HEADER.TimeDateStamp)
