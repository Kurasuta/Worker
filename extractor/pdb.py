from datetime import datetime
from .base import BaseExtractor


class Pdb(BaseExtractor):
    def __init__(self, data, pe):
        self.data = data
        self.pe = pe

    def extract(self, sample):
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_DEBUG'):
            return

        if len(self.pe.DIRECTORY_ENTRY_DEBUG) > 1:
            raise Exception('Found %i debug directories' % len(self.pe.DIRECTORY_ENTRY_DEBUG))

        for debug_data in self.pe.DIRECTORY_ENTRY_DEBUG:
            # TODO sample.pdb_guid
            # guid_data2 = struct.pack('<H', debug_data.entry.Signature_Data1).encode('hex')
            # guid_data2 = struct.pack('<H', debug_data.entry.Signature_Data2).encode('hex')
            # guid_data3 = struct.pack('<H', debug_data.entry.Signature_Data3).encode('hex')
            # guid_data4 = struct.pack('<Q', debug_data.entry.Signature_Data4).encode('hex')
            # print('{{{}-{}-{}-{}}}'.format(guid_data1, guid_data2, guid_data3, guid_data4))

            sample.debug_timestamp = datetime.utcfromtimestamp(debug_data.struct.TimeDateStamp)
            sample.pdb_path = debug_data.entry.PdbFileName.decode('utf-8').strip('\0')
            # TODO sample.pdb_age
            # TODO sample.pdb_timestamp
