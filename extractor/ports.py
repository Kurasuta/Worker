from lib.data import SampleExport, SampleImport
from .base import BaseExtractor


class Ports(BaseExtractor):
    def __init__(self, pe):
        self.pe = pe

    def extract(self, sample):
        sample.imphash = self.pe.get_imphash()

        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            rva = self.pe.DIRECTORY_ENTRY_EXPORT.struct.Name

            export_name = self.pe.get_string_at_rva(rva)
            if export_name:
                sample.export_name = export_name.decode('utf-8')
            if len(self.pe.DIRECTORY_ENTRY_EXPORT.symbols) > 0:
                sample.exports = []
                for pe_export in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    export = SampleExport()
                    export.address = self.pe.OPTIONAL_HEADER.ImageBase + pe_export.address
                    export.name = pe_export.name
                    export.ordinal = pe_export.ordinal
                    sample.exports.append(export)

        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            if len(self.pe.DIRECTORY_ENTRY_IMPORT) > 0:
                sample.imports = []
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    for pe_imp in entry.imports:
                        imp = SampleImport()
                        imp.dll_name = entry.dll.decode('utf-8')
                        imp.address = pe_imp.address
                        if pe_imp.name:
                            imp.name = pe_imp.name.decode('utf-8')
                        sample.imports.append(imp)
