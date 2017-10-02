class Sample(object):
    def __init__(self):
        self.hash_sha256 = None
        self.hash_md5 = None
        self.hash_sha1 = None

        self.ssdeep = None

        self.magic_id = None
        self.file_size = None
        self.entry_point = None
        self.overlay_size = None
        self.overlay_sha256 = None
        self.build_timestamp = None

        self.debug_timestamp = None
        self.pdb_timestamp = None
        self.pdb_path = None
        self.pdb_guid = None
        self.pdb_age = None

        self.export_name = None
        self.export_table_timestamp = None
        self.resource_timestamp = None
        self.certificate_signing_timestamp = None

        self.sections = []

    def __repr__(self):
        return '<Sample %s,%s,%s>' % (self.hash_sha256, self.hash_md5, self.hash_sha1)


class SampleSection(object):
    def __init(self):
        self.hash_sha256 = None
        self.virtual_address = None
        self.virtual_size = None
        self.raw_size = None
        self.name = None

    def __repr__(self):
        return '<Section %s,%s,%s,%s,%s>' % (
            self.hash_sha256,
            self.virtual_address,
            self.virtual_size,
            self.raw_size,
            self.name
        )


class JsonFactory(object):
    @staticmethod
    def _format_int(data):
        return '%i' % data

    @staticmethod
    def _format_timestamp(data):
        return '%s' % data  # TODO

    def from_sample(self, sample):
        # TODO magic_id
        d = {}
        if sample.hash_sha256 is not None: d['hash_sha256'] = sample.hash_sha256
        if sample.hash_md5 is not None: d['hash_md5'] = sample.hash_md5
        if sample.hash_sha1 is not None: d['hash_sha1'] = sample.hash_sha1

        if sample.ssdeep is not None: d['ssdeep'] = sample.ssdeep

        if sample.file_size is not None: d['file_size'] = self._format_int(sample.file_size)
        if sample.entry_point is not None: d['entry_point'] = self._format_int(sample.entry_point)
        if sample.overlay_size is not None: d['overlay_size'] = self._format_int(sample.overlay_size)
        if sample.overlay_sha256 is not None: d['overlay_sha256'] = sample.overlay_sha256
        if sample.build_timestamp is not None: d['build_timestamp'] = self._format_timestamp(sample.build_timestamp)

        if sample.debug_timestamp is not None: d['debug_timestamp'] = self._format_timestamp(sample.debug_timestamp)
        if sample.pdb_timestamp is not None: d['pdb_timestamp'] = self._format_timestamp(sample.pdb_timestamp)
        if sample.pdb_path is not None: d['pdb_path'] = sample.pdb_path
        if sample.pdb_guid is not None: d['pdb_guid'] = sample.pdb_guid
        if sample.pdb_age is not None: d['pdb_age'] = sample.pdb_age

        if sample.export_name is not None: d['export_name'] = sample.export_name
        if sample.export_table_timestamp is not None: d['export_table_timestamp'] = sample.export_table_timestamp
        if sample.resource_timestamp is not None:
            d['resource_timestamp'] = self._format_timestamp(sample.resource_timestamp)
        if sample.certificate_signing_timestamp is not None:
            d['certificate_signing_timestamp'] = self._format_timestamp(sample.certificate_signing_timestamp)

        if sample.sections:
            d['sections'] = [
                {
                    'hash_sha256': section.hash_sha256,
                    'name': section.name,
                    'virtual_address': section.virtual_address,
                    'virtual_size': section.virtual_size,
                    'raw_size': section.raw_size
                } for section in sample.sections
            ]

        return d
