from lib import entropy
from .base import BaseExtractor


class File(BaseExtractor):
    def __init__(self, data, pe):
        self.data = data
        self.pe = pe

    def extract(self, sample):
        sample.size = len(self.data)
        sample.entropy = entropy(self.data)
        sample.entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
