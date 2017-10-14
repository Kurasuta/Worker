import argparse
import importlib
import inspect
import logging
import os
import sys
from pprint import pprint

import pefile
import raven

from graphite import Graphite
from lib import RegexFactory
from lib.data import Sample, JsonFactory
from peyd.peyd import PEiDDataBase

logging.basicConfig(format='%(asctime)s %(message)s')
logger = logging.getLogger('KurasutaWorker')

script_folder = os.path.dirname(os.path.realpath(__file__))
sys.path.append(script_folder)

parser = argparse.ArgumentParser(description='extracts metadata from PE file (part of the Kurasuta project)')
parser.add_argument('--debug', action='store_true', help='Show debugging information')
parser.add_argument('--pretty', action='store_true', help='Uses pretty print')
parser.add_argument('--filter', help='Specify pattern that output fields must match')
parser.add_argument('file_name', metavar='FILENAME', help='file to process')
args = parser.parse_args()

logger.setLevel(logging.DEBUG if args.debug else logging.WARNING)

if 'RAVEN_CLIENT_STRING' in os.environ:
    raven = raven.Client(os.environ['RAVEN_CLIENT_STRING'])
else:
    raven = None
    logger.warning('Environment variable RAVEN_CLIENT_STRING does not exist. No logging to Sentry is performed.')

if 'GRAPHITE_SERVER' in os.environ:
    graphite = Graphite(os.environ['GRAPHITE_SERVER'])
else:
    graphite = None
    logger.warning('Environment variable GRAPHITE_SERVER does not exist. No logging to Graphite is performed.')

file_data = open(args.file_name, 'rb').read()
pe = pefile.PE(data=file_data)
peyd = PEiDDataBase()
peyd.readfile(os.path.join(os.path.dirname(__file__), 'peyd', 'peyd.txt'))

regex_factory = RegexFactory()


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
                raise Exception('Duplicate Extractor name: %s' % name)
            if not inspect.isclass(class_object):
                continue
            signature = inspect.signature(class_object.__init__)

            kwargs = {}
            for parameter in signature.parameters:
                if parameter == 'self': continue
                if parameter == 'pe': kwargs['pe'] = pe
                if parameter == 'data': kwargs['data'] = file_data
                if parameter == 'logger': kwargs['logger'] = logger
                if parameter == 'regex_factory': kwargs['regex_factory'] = regex_factory
                if parameter == 'peyd': kwargs['peyd'] = peyd

            if len(class_object.__bases__) != 1:
                continue
            base_class = class_object.__bases__[0]
            if base_class.__name__ != 'BaseExtractor':
                continue

            extractors[name] = class_object(**kwargs)
    return extractors


sample = Sample()
extractors = get_extractors().values()
logger.debug('Enabled Extractors: %s' % extractors)
for extractor in extractors:
    try:
        extractor.extract(sample)
    except Exception as e:
        logger.error('%s' % e)
        if raven:
            raven.captureException()

out = JsonFactory(args.filter).from_sample(sample)
if args.pretty:
    pprint(out)
else:
    print(out)
