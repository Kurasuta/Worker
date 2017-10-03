from datetime import datetime
from .base import BaseExtractor
from lib import null_terminate_and_decode_utf8


class Pdb(BaseExtractor):
    def __init__(self, data, pe):
        self.data = data
        self.pe = pe

    def extract(self, sample):
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_DEBUG'):
            return

        debug_timestamps = []
        pdb_paths = []
        sample.debug_directory_count = len(self.pe.DIRECTORY_ENTRY_DEBUG)

        for debug_data in self.pe.DIRECTORY_ENTRY_DEBUG:
            # TODO sample.pdb_age
            # TODO sample.pdb_timestamp
            # TODO sample.pdb_guid
            # guid_data2 = struct.pack('<H', debug_data.entry.Signature_Data1).encode('hex')
            # guid_data2 = struct.pack('<H', debug_data.entry.Signature_Data2).encode('hex')
            # guid_data3 = struct.pack('<H', debug_data.entry.Signature_Data3).encode('hex')
            # guid_data4 = struct.pack('<Q', debug_data.entry.Signature_Data4).encode('hex')
            # print('{{{}-{}-{}-{}}}'.format(guid_data1, guid_data2, guid_data3, guid_data4))

            if debug_data.struct.TimeDateStamp:
                debug_timestamps.append(debug_data.struct.TimeDateStamp)
            if hasattr(debug_data.entry, 'PdbFileName'):
                pdb_paths.append(null_terminate_and_decode_utf8(debug_data.entry.PdbFileName))

        debug_timestamps = list(set(debug_timestamps))
        pdb_paths = list(set(pdb_paths))
        if len(debug_timestamps) > 1 or len(pdb_paths) > 1:
            raise Exception('Found %i debug timestamps and %i pdb paths.' % (len(debug_timestamps), len(pdb_paths)))

        if debug_timestamps: sample.debug_timestamp = datetime.utcfromtimestamp(debug_timestamps[0])
        if pdb_paths: sample.pdb_path = pdb_paths[0]
