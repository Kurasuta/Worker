from lib.regex import entropy
import ssdeep
import hashlib
from .base import BaseExtractor


class Overlay(BaseExtractor):
    def __init__(self, data, pe):
        self.data = data
        self.pe = pe

    def extract(self, sample):
        overlay = self.data[self.pe.get_overlay_data_start_offset()::]
        sample.overlay_sha256 = hashlib.sha256(overlay).hexdigest()
        sample.overlay_size = len(overlay)
        sample.overlay_ssdeep = ssdeep.hash(overlay)
        sample.overlay_entropy = entropy(overlay)
