from .base import BaseExtractor


class FileSize(BaseExtractor):
    def __init__(self, data):
        self.data = data

    def extract(self, sample):
        sample.size = len(self.data)
