import hashlib
from lib import entropy
import ssdeep
from data import SampleResource
from .base import BaseExtractor


class Resources(BaseExtractor):
    def __init__(self, data, pe, logger):
        self.data = data
        self.pe = pe
        self.logger = logger

    def extract(self, sample):
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return

        def extract_resource(type_pair, name_pair, language_pair, offset, size):
            data = self.pe.get_data(offset, size)
            if len(data) != size:
                raise Exception('Data of size %s extracted eventhough size had value %s' % (len(data), size))

            resource = SampleResource()

            resource.hash_sha256 = hashlib.sha256(data).hexdigest()
            resource.offset = offset
            resource.size = size

            resource.ssdeep = ssdeep.hash(data)
            resource.entropy = entropy(data)

            resource.type_id, resource.type_str = type_pair
            resource.name_id, resource.name_str = name_pair
            resource.language_id, resource.language_str = language_pair

            sample.resources.append(resource)
            self.logger.debug('%s%s' % ('    ' * 4, resource))

        for pe_resource in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            self.traverse(pe_resource, extract_resource)

    def traverse(self, pe_resource, yield_callback, depth=1, type_pair=None, name_pair=None):
        self.logger.debug('%s%s' % ('    ' * depth, 'id=%s, name=%s' % (pe_resource.id, pe_resource.name)))

        if depth == 1:  # TYPE level
            type_pair = (pe_resource.id, pe_resource.name)
        elif depth == 2:  # NAME level
            name_pair = (pe_resource.id, pe_resource.name)
        elif depth == 3:  # LANG level
            language_pair = (pe_resource.id, pe_resource.name)
            yield_callback(
                type_pair, name_pair, language_pair,
                pe_resource.data.struct.OffsetToData, pe_resource.data.struct.Size
            )
        else:
            raise Exception('Found resource tree structure with depth > 3')

        if pe_resource.struct.DataIsDirectory:
            for child_pe_resource in pe_resource.directory.entries:
                self.traverse(child_pe_resource, yield_callback, depth + 1, type_pair, name_pair)
