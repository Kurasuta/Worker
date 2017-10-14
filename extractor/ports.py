from lib.data import SampleExport, SampleImport
from .base import BaseExtractor


class Ports(BaseExtractor):
    def __init__(self, pe):
        self.pe = pe

    def extract(self, sample):
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            rva = self.pe.DIRECTORY_ENTRY_EXPORT.struct.Name

            sample.export_name = self.pe.get_string_at_rva(rva)
            if len(self.pe.DIRECTORY_ENTRY_EXPORT.symbols) > 0:
                sample.exports = []
                for pe_export in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    export = SampleExport()
                    export.address = hex(self.pe.OPTIONAL_HEADER.ImageBase + pe_export.address)
                    export.name = pe_export.name
                    export.ordinal = pe_export.ordinal
                    sample.exports.append(export)

        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            if len(self.pe.DIRECTORY_ENTRY_IMPORT) > 0:
                sample.imports = []
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    for pe_imp in entry.imports:
                        imp = SampleImport()
                        imp.dll_name = entry.dll
                        imp.address = pe_imp.address
                        imp.name = pe_imp.name
                        sample.imports.append(imp)
