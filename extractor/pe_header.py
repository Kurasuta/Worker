from .base import BaseExtractor


class PeHeaderPdb(BaseExtractor):
    def __init__(self, pe):
        self.pe = pe

    def extract(self, sample):
        sample.entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
