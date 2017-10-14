from datetime import datetime
from .base import BaseExtractor
from lib.regex import null_terminate_and_decode_utf8


class Pdb(BaseExtractor):
    def __init__(self, pe):
        self.pe = pe

    def extract(self, sample):
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_DEBUG'):
            return

        debug_timestamps = []
        pdb_paths = []
        pdb_ages = []
        pdb_signatures = []
        pdb_guids = []
        sample.debug_directory_count = len(self.pe.DIRECTORY_ENTRY_DEBUG)

        for debug_data in self.pe.DIRECTORY_ENTRY_DEBUG:
            if not hasattr(debug_data, 'entry'):
                continue
            if hasattr(debug_data.entry, 'CvSignature'):
                pdb_signatures.append(debug_data.entry.CvSignature)
            guid = '-'.join([
                '%x' % getattr(debug_data.entry, e)
                for e in dir(debug_data.entry)
                if e.startswith('Signature_Data')
            ])
            if guid: pdb_guids.append(guid)

            if hasattr(debug_data.entry, 'Age'):
                pdb_ages.append(debug_data.entry.Age)
            if debug_data.struct.TimeDateStamp:
                debug_timestamps.append(debug_data.struct.TimeDateStamp)
            if hasattr(debug_data.entry, 'PdbFileName'):
                pdb_paths.append(null_terminate_and_decode_utf8(debug_data.entry.PdbFileName))

        debug_timestamps = list(set(debug_timestamps))
        if len(debug_timestamps) > 1:
            raise Exception('Found %i debug timestamps.' % len(debug_timestamps))

        pdb_ages = list(set(pdb_ages))
        if len(pdb_paths) > 1:
            raise Exception('Found %i debug ages.' % len(pdb_ages))

        pdb_paths = list(set(pdb_paths))
        if len(pdb_paths) > 1:
            raise Exception('Found %i debug paths.' % len(pdb_paths))

        pdb_signatures = list(set(pdb_signatures))
        if len(pdb_signatures) > 1:
            raise Exception('Found %i pdb signatures.' % len(pdb_signatures))

        pdb_guids = list(set(pdb_guids))
        if len(pdb_guids) > 1:
            raise Exception('Found %i pdb GUIDs.' % len(pdb_guids))

        if debug_timestamps: sample.debug_timestamp = datetime.utcfromtimestamp(debug_timestamps[0])
        if pdb_ages: sample.pdb_age = pdb_ages[0]
        if pdb_paths: sample.pdb_path = pdb_paths[0]
        if pdb_signatures: sample.pdb_signature = pdb_signatures[0]
        if pdb_guids: sample.pdb_guid = pdb_guids[0]
