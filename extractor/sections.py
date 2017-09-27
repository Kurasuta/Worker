import hashlib
from data import SampleSection
from .base import BaseExtractor


class Sections(BaseExtractor):
    def __init__(self, data, pe):
        self.data = data
        self.pe = pe

    def extract(self, sample):
        if not hasattr(self.pe, 'sections'):
            return
        for pe_section in self.pe.sections:
            section = SampleSection()
            section.hash_sha256 = hashlib.sha256(pe_section.get_data()).hexdigest()
            section.name = pe_section.Name.decode('utf-8').replace('\0', '')
            section.virtual_address = pe_section.VirtualAddress
            section.virtual_size = pe_section.Misc_VirtualSize
            section.raw_size = pe_section.SizeOfRawData
            sample.sections.append(section)
