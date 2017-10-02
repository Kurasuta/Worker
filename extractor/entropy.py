import entropy
from .base import BaseExtractor


class Entropy(BaseExtractor):
    def __init__(self, data):
        self.data = data

    def extract(self, sample):
        sample.entropy = entropy.shannon_entropy(self.data)
        # TODO calculate entropy for every section
        # TODO calculate entropy for every resource
