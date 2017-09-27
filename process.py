import argparse
import pefile
import os
import inspect
import importlib
from pprint import pprint

from data import Sample, JsonFactory

parser = argparse.ArgumentParser(description='extracts metadata from PE file (part of the Kurasuta project)')
parser.add_argument('file_name', metavar='FILENAME', help='file to process')

args = parser.parse_args()

file_data = open(args.file_name, 'rb').read()
pe = pefile.PE(data=file_data)
extractor_folder = "extractor"


def get_extractors():
    extractors = []
    for extractor_file_name in os.listdir(extractor_folder):
        if not extractor_file_name.endswith('.py'):
            continue

        if not os.path.isfile(os.path.join(extractor_folder, extractor_file_name)):
            continue

        module = importlib.import_module('.'.join([extractor_folder, extractor_file_name[:-3]]))
        for name, class_object in inspect.getmembers(module):
            if not inspect.isclass(class_object):
                continue
            signature = inspect.signature(class_object.__init__)

            kwargs = {}
            for parameter in signature.parameters:
                if parameter == 'self': continue
                if parameter == 'pe': kwargs['pe'] = pe
                if parameter == 'data': kwargs['data'] = file_data

            extractors.append(class_object(**kwargs))
    return extractors


sample = Sample()
for extractor in get_extractors():
    extractor.extract(sample)

pprint(JsonFactory().from_sample(sample))
