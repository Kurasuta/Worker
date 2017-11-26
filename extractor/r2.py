from lib.sample import SampleFunction
from .base import BaseExtractor
import r2pipe
import json
import re
import hashlib
import crcmod


class R2(BaseExtractor):
    def __init__(self, file_name):
        self.file_name = file_name

    def extract(self, sample):
        r2 = r2pipe.open(self.file_name)
        r2.cmd('aaa')  # analyse all
        sample.functions = []
        for r2_func in json.loads(r2.cmd('aflj')):  # list all functions (to JSON)
            sample_func = SampleFunction()
            sample_func.offset = r2_func['offset']
            sample_func.size = r2_func['size']
            sample_func.real_size = r2_func['realsz']
            sample_func.name = r2_func['name']
            sample_func.calltype = r2_func['calltype']
            sample_func.cc = r2_func['cc']
            sample_func.cost = r2_func['cost']
            sample_func.ebbs = r2_func['ebbs']
            sample_func.edges = r2_func['edges']
            sample_func.indegree = r2_func['indegree']
            sample_func.nargs = r2_func['nargs']
            sample_func.nbbs = r2_func['nbbs']
            sample_func.nlocals = r2_func['nlocals']
            sample_func.outdegree = r2_func['outdegree']
            sample_func.type = r2_func['type']

            sample_func.raw = json.loads(r2.cmd('pdj @' + r2_func['name']))  # disassemble (to JSON)
            opcodes = [instr['opcode'] for instr in sample_func.raw if 'opcode' in instr]
            cleaned_opcodes = [self._clean_ops(opcode) for opcode in opcodes]

            data = (''.join(opcodes)).encode('utf-8')
            sample_func.opcodes_sha256 = hashlib.sha256(data).hexdigest()
            sample_func.opcodes_crc32 = crcmod.Crc(0x104c11db7).new(data).hexdigest().lower()

            cleaned_data = (''.join(cleaned_opcodes)).encode('utf-8')
            sample_func.cleaned_opcodes_sha256 = hashlib.sha256(cleaned_data).hexdigest()
            sample_func.cleaned_opcodes_crc32 = crcmod.Crc(0x104c11db7).new(cleaned_data).hexdigest().lower()

            sample.functions.append(sample_func)

    @staticmethod
    def _clean_ops(opcode):
        ret = opcode
        ret = re.sub('\\b0x[0-9a-f]{6}\\b', 'CLEANED', ret)
        ret = re.sub('\\.[0-9a-f]{8}\\b', '.CLEANED', ret)
        return ret
