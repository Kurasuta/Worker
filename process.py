import argparse
import pefile
import os
import sys
import inspect
import importlib
from pprint import pprint

from data import Sample, JsonFactory

script_folder = os.path.dirname(os.path.realpath(__file__))
sys.path.append(script_folder)

parser = argparse.ArgumentParser(description='extracts metadata from PE file (part of the Kurasuta project)')
parser.add_argument('file_name', metavar='FILENAME', help='file to process')
args = parser.parse_args()

file_data = open(args.file_name, 'rb').read()
pe = pefile.PE(data=file_data)


def get_extractors():
    extractors = {}
    for extractor_file_name in os.listdir(os.path.join(script_folder, 'extractor')):
        if not extractor_file_name.endswith('.py'):
            continue

        if not os.path.isfile(os.path.join(script_folder, 'extractor', extractor_file_name)):
            continue

        module = importlib.import_module('.'.join(['extractor', extractor_file_name[:-3]]))
        for name, class_object in inspect.getmembers(module):
            if name in extractors.keys():
                continue
            if not inspect.isclass(class_object):
                continue
            signature = inspect.signature(class_object.__init__)

            kwargs = {}
            for parameter in signature.parameters:
                if parameter == 'self': continue
                if parameter == 'pe': kwargs['pe'] = pe
                if parameter == 'data': kwargs['data'] = file_data

            if len(class_object.__bases__) != 1:
                continue
            base_class = class_object.__bases__[0]
            if base_class.__name__ != 'BaseExtractor':
                continue

            extractors[name] = class_object(**kwargs)
    return extractors


sample = Sample()
for extractor in get_extractors().values():
    extractor.extract(sample)

pprint(JsonFactory().from_sample(sample))
