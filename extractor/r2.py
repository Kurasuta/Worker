from .base import BaseExtractor
import r2pipe


class R2(BaseExtractor):
    def __init__(self, file_name):
        self.r2 = r2pipe.open(file_name)

    def extract(self, sample):
        self.r2.cmd('aaa')  # analyse all
