import entropy
import ssdeep
import hashlib
from .base import BaseExtractor


class Overlay(BaseExtractor):
    def __init__(self, data, pe):
        self.data = data
        self.pe = pe

    def extract(self, sample):
        if len(self.pe.sections) == 0:
            return
        first_section = self.pe.sections[-1]
        pe_size = first_section.PointerToRawData + first_section.SizeOfRawData

        overlay = self.data[pe_size:]
        sample.overlay_sha256 = hashlib.sha256(overlay).hexdigest()
        sample.overlay_size = len(overlay)
        sample.overlay_ssdeep = ssdeep.hash(overlay)
        sample.overlay_entropy = entropy.shannon_entropy(overlay)
