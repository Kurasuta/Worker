import hashlib
from lib import entropy, null_terminate_and_decode_utf8
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

        sample.code_histogram = dict([(i, 0) for i in range(256)])
        for pe_section in self.pe.sections:
            section = SampleSection()
            data = pe_section.get_data()

            section.hash_sha256 = hashlib.sha256(data).hexdigest()
            section.name = null_terminate_and_decode_utf8(pe_section.Name)
            if 'text' in section.name or 'CODE' in section.name:
                for i in list(data):
                    sample.code_histogram[i] += 1
            section.virtual_address = pe_section.VirtualAddress
            section.virtual_size = pe_section.Misc_VirtualSize
            section.raw_size = pe_section.SizeOfRawData
            section.entropy = entropy(data)
            section.ssdeep = ssdeep.hash(data)
            sample.sections.append(section)
