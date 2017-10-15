from datetime import datetime
from .base import BaseExtractor
from lib.regex import null_terminate_and_decode_utf8
from lib.data import SampleDebugDirectory


class Pdb(BaseExtractor):
    def __init__(self, pe):
        self.pe = pe

    def extract(self, sample):
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_DEBUG'):
            return

        directories = []
        for debug_data in self.pe.DIRECTORY_ENTRY_DEBUG:
            if not hasattr(debug_data, 'entry'):
                continue
            directory = SampleDebugDirectory()
            if hasattr(debug_data.entry, 'CvSignature'):
                directory.signature = debug_data.entry.CvSignature
            sig_data = [
                '%x' % getattr(debug_data.entry, e)
                for e in dir(debug_data.entry)
                if e.startswith('Signature_Data')
            ]
            if sig_data: directory.guid = '-'.join(sig_data)

            if hasattr(debug_data.entry, 'Age'):
                directory.age = debug_data.entry.Age
            if debug_data.struct.TimeDateStamp:
                directory.timestamp = datetime.utcfromtimestamp(debug_data.struct.TimeDateStamp)
            if hasattr(debug_data.entry, 'PdbFileName'):
                directory.path = null_terminate_and_decode_utf8(debug_data.entry.PdbFileName)

            if directory.signature or directory.guid or directory.age or directory.timestamp or directory.path:
                directories.append(directory)

        if directories:
            sample.debug_directories = directories
