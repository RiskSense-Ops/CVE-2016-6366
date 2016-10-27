# CVE-2016-6366

Public repository for improvements to the EXTRABACON exploit, a remote code execution for Cisco ASA written by the Equation Group (NSA) and leaked by the Shadow Brokers.
 
There is improved shellcode, a LINA offset finder script, a Metasploit module, and extrabacon-2.0.

We are adding patches for most versions of 8.x and 9.x in the near future after we test all versions on real hardware.

This is using improved shellcode, has less stages than the Equation Group version making it more reliable. This makes the SNMP payload packet ~150 less bytes. Also, the leaked version only supports 8.x, we have it working on 9.x versions.

### Supported Versions (so far)

Using the Lina offset finder script, it should be trivial to support all vulnerable x86 versions. We are working on doing just that. NOTE: x64 (9.6+?) introduces DEP and ASLR. The offset finder and generic payload will not work. It should still be possible to easily dos these versions though.

Open an issue if you would like us to support a specific version. It will move to the front of the line.

8.x
- 8.0(2)
- 8.0(3)
- 8.0(3)6
- 8.0(4)
- 8.0(4)32
- 8.0(5)
- 8.2(1)
- 8.2(2)
- 8.2(3)
- 8.2(4)
- 8.2(5)
- 8.2(5)33 `*`
- 8.2(5)41 `*`
- 8.2(5)55 `*`
- 8.3(1)
- 8.3(2)
- 8.3(2)39 `*`
- 8.3(2)40 `*`
- 8.3(2)-npe `*` `**`
- 8.4(1)
- 8.4(2)
- 8.4(3)
- 8.4(4)
- 8.4(4)1 `*`
- 8.4(4)3 `*`
- 8.4(4)5 `*`
- 8.4(4)9 `*`
- 8.4(6)5 `*`
- 8.4(7) `*`

9.x
- 9.0(1) `*`
- 9.1(1)4 `*`
- 9.2(1) `*`
- 9.2(2)8 `*`
- 9.2(3) `*`
- 9.2(4) `*`
- 9.2(4)13 `*`

`*` new version support not part of the original Shadow Brokers leak

`**` We currently can't distinguish between normal and NPE versions from the SNMP strings. We've commented out the NPE offsets, as NPE is very rare (it is for exporting to places where encryption is crappy), but in the future, we'd like to incorporate these versions. Perhaps as a bool option?

### Metasploit

`use auxiliary/admin/cisco/cisco_asa_extrabacon`

https://github.com/rapid7/metasploit-framework/pull/7359

Our initial pull request was merged into Metasploit master branch. We will still be contributing more offsets, which may be available here sooner depending on latency of future pull requests.

### Contributing
If you can test ASA versions, consider forking this project and generating payloads. We could mass-generate the payloads, but we want to test to make sure every payload exits cleanly.

You can add new payloads to the `extrabacon-2.0/improved/` folder after using `lina-offsets.py` to generate the file. Modules are named `shellcode_verstring.py`, where verstring is the version string returned by the ASA, with periods . replaced with underscores _

Also submit pull requests stripping any unnecessary Python from the ExtraBacon 2.0 code.

### Lina offset finder
`python2 ./lina-offsets.py asa_lina_XXX.elf`

Will automatically generate necessary offsets to port the exploit to other versions of ASA.

Right now, it takes us longer to load a version of ASA firmware and test it, than it does to generate offsets for a specific version.

The only thing the script doesn't calculate is FIX_EBP, which is usually 0x48 (72) or 0x58 (88). It seems like 8.4(1) and greater use 0x48.

You can extract Lina like this:

`binwalk -e asaXXX-k8.bin`
`cd _asaXXX-extracted`
`cpio -idv < rootfs.img`
`cp asa/bin/lina /tmp/linaXXX`

### Licenses

- ExtraBacon 2.0 Python code is GPLv2 (as it uses Scapy)
- Metasploit module is MSF license (3-clause BSD)
- Everything else is MIT


### References
- http://zerosum0x0.blogspot.com/2016/09/reverse-engineering-cisco-asa-for.html
- https://blog.silentsignal.eu/2016/08/25/bake-your-own-extrabacon/
- https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160817-asa-snmp
