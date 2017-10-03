import hashlib
from lib import entropy
import ssdeep
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
            data = pe_section.get_data()

            section.hash_sha256 = hashlib.sha256(data).hexdigest()
            # simulate NULL termination and try to avoid exceptions due to malformations
            section.name = pe_section.Name.decode('utf-8', 'ignore').split('\x00', 1)[0]
            section.virtual_address = pe_section.VirtualAddress
            section.virtual_size = pe_section.Misc_VirtualSize
            section.raw_size = pe_section.SizeOfRawData
            section.entropy = entropy(data)
            section.ssdeep = ssdeep.hash(data)
            sample.sections.append(section)
