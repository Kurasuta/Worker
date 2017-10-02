import ssdeep
from .base import BaseExtractor


class SSDeep(BaseExtractor):
    def __init__(self, data, pe):
        self.data = data
        self.pe = pe

    def extract(self, sample):
        # TODO implement dependency relation on extractors
        # TODO implement possiblity for extractor to store temporary data (section/resource data)
        # TODO calculate ssdeep of sections and resources
        sample.ssdeep = ssdeep.hash(self.data)
