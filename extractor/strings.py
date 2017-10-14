from .base import BaseExtractor
from lib.regex import strings
from base64 import b64decode
import zlib


class Strings(BaseExtractor):
    def __init__(self, data, pe, regex_factory):
        self.data = data
        self.regex_factory = regex_factory

    def extract(self, sample):
        sample.strings_count_of_length_at_least_10 = len(list(strings(self.data, 10)))

        sample.heuristic_iocs = []
        sample.strings_count = 0
        for s in strings(self.data):
            sample.heuristic_iocs += self._heuristic_ioc_extraction('%s' % s)
            sample.strings_count += 1
        sample.heuristic_iocs = list(set(sample.heuristic_iocs))

    def _heuristic_ioc_extraction(self, data):
        ret = []
        stack = [data]
        while stack:
            for match in self.regex_factory.get_base64().findall(stack.pop()):
                if len(match) < 20: continue
                decoded = b64decode(match)
                if decoded[:4] == '\x1F\x8B\x08\x00':  # zlib magic
                    decoded = zlib.decompress(decoded, 16 + zlib.MAX_WBITS)

                decoded = '%s' % decoded
                if decoded:
                    stack.append(decoded)
                    stack.append(decoded.replace('\0', ''))  # covers wide strings
                    ret += self._extract_ips(decoded) + self._extract_domains(decoded)

        return list(set(ret))

    def _extract_ips(self, data):
        return [item for item in self.regex_factory.get_ip().findall(data) if '0.0.0' not in item]

    def _extract_domains(self, data):
        ret = []
        for needle in ['http://', 'https://']:
            for potential_domain in data.split(needle)[1:]:
                ret.append(self.regex_factory.get_domain().match(potential_domain).group())
        return list(set(ret))
