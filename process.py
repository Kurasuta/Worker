import argparse
import importlib
import inspect
import logging
import os
import json
import sys
from pprint import pprint

import pefile

from graphite import Graphite
from lib.performance import PerformanceTimer, NullTimer, SubTimer
from lib.regex import RegexFactory
from lib.data import Sample, JsonFactory
from peyd.peyd import PEiDDataBase

logging.basicConfig(format='%(asctime)s %(message)s')
logger = logging.getLogger('KurasutaWorker')
script_folder = os.path.dirname(os.path.realpath(__file__))
sys.path.append(script_folder)

parser = argparse.ArgumentParser(description='extracts metadata from PE file (part of the Kurasuta project)')
parser.add_argument('--debug', action='store_true', help='Show debugging information')
parser.add_argument('--pretty', action='store_true', help='Uses pretty print')
parser.add_argument('--performance', action='store_true', help='Measure performance and output report')
parser.add_argument('--filter', help='Specify pattern that output fields must match')
parser.add_argument('file_name', metavar='FILENAME', help='file to process')
args = parser.parse_args()

timer = PerformanceTimer(logger) if args.performance else NullTimer()
timer.mark('start')
logger.setLevel(logging.DEBUG if args.debug else logging.WARNING)

if 'RAVEN_CLIENT_STRING' in os.environ:
    import raven

    sentry = raven.Client(os.environ['RAVEN_CLIENT_STRING'])
else:
    sentry = None
    logger.warning('Environment variable RAVEN_CLIENT_STRING does not exist. No logging to Sentry is performed.')

if 'GRAPHITE_SERVER' in os.environ:
    graphite = Graphite(os.environ['GRAPHITE_SERVER'])
else:
    graphite = None
    logger.warning('Environment variable GRAPHITE_SERVER does not exist. No logging to Graphite is performed.')

regex_factory = RegexFactory()
timer.mark('read_file')
file_data = open(args.file_name, 'rb').read()
timer.mark('parse_pe')
pe = pefile.PE(data=file_data)
timer.mark('init_peyd')
peyd = PEiDDataBase()
peyd.readfile(os.path.join(os.path.dirname(__file__), 'peyd', 'peyd.txt'))


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

            if len(class_object.__bases__) != 1:
                continue
            base_class = class_object.__bases__[0]
            if base_class.__name__ != 'BaseExtractor':
                continue

            kwargs = {}
            for parameter in signature.parameters:
                if parameter == 'self': continue
                if parameter == 'pe': kwargs['pe'] = pe
                if parameter == 'data': kwargs['data'] = file_data
                if parameter == 'logger': kwargs['logger'] = logger
                if parameter == 'regex_factory': kwargs['regex_factory'] = regex_factory
                if parameter == 'peyd': kwargs['peyd'] = peyd
                if parameter == 'timer': kwargs['timer'] = timer

            extractors[name] = class_object(**kwargs)
    return extractors


timer.mark('read_extractors')
sample = Sample()
extractors = get_extractors().values()
logger.debug('Enabled Extractors: %s' % extractors)
for extractor in extractors:
    timer.mark('extractor_%s' % extractor.__class__.__name__)
    try:
        extractor.extract(sample)
    except Exception as e:
        logger.error('%s' % e)
        if sentry:
            sentry.captureException()

timer.mark('output')
out = JsonFactory(args.filter).from_sample(sample)
if args.pretty:
    pprint(out)
else:
    print(json.dumps(out))
timer.mark('end')

if args.performance:
    from terminaltables import AsciiTable as TerminalTable

    table_data = [['Operation', 'perf_count', 'process_time']]
    for i in range(1, len(timer) - 2):
        perf_count_diff = timer[i + 1].perf_count - timer[i].perf_count
        process_time_diff = timer[i + 1].process_time - timer[i].process_time
        table_data.append([timer[i].caption, '%.7f' % perf_count_diff, '%.7f' % process_time_diff])

    print(TerminalTable(table_data).table)
