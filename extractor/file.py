from lib import entropy
from .base import BaseExtractor


class File(BaseExtractor):
    def __init__(self, data):
        self.data = data

    def extract(self, sample):
        sample.size = len(self.data)
        sample.entropy = entropy(self.data)
        # TODO calculate entropy for every section
