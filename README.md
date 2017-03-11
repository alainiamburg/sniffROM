# sniffROM
Reconstructs flash memory contents from passively captured READ/WRITE commands in a Saleae logic analyzer exported capture file.

Features:
* Preserves memory addresses.
* Currently supports SPI flash chips.
```
usage: sniffROM.py [-h] [--addrlen [{2,3}]] [--endian [{msb,lsb}]]
                   [--filter [{r,w,rw}]] [-o [O]] [--summary] [--verbose]
                   input_file

positional arguments:
  input_file            Saleae Logic SPI Analyzer Export File (.csv)

optional arguments:
  -h, --help            show this help message and exit
  --addrlen [{2,3}]     Length of address in bytes (default is 3)
  --endian [{msb,lsb}]  Endianness of address bytes (default is msb first)
  --filter [{r,w,rw}]   Parse READ, WRITE, or READ and WRITE commands (default
                        is rw)
  -o [O]                Output binary image file (default is output.bin)
  --summary             Also dump statistics
  --verbose, -v         Increase verbosity
```
Examples:
Probe a SPI flash chip in a device, and take a Saleae Logic capture during device boot-up. Export SPI analyzer in CSV.

<br>
1)
```
$ python sniffROM.py -o spiflash_out.bin --summary spansion_spiflash_onboot.csv
Finished parsing input file

Trimming pad bytes...

Rebuilt image: 664784 bytes (saved to spiflash_out.bin)
Captured data: 234598 bytes (35.29%) (46 bytes from WRITE commands)

Summary:
Command 0xab: 0 instances (Read Device ID)
Command 0x01: 4 instances (Write Status Register)
Command 0x02: 46 instances (Page Program)
Command 0x03: 59216 instances (Read Data)
Command 0x04: 0 instances (Write Disable)
Command 0x05: 50 instances (Read Status Register 1)
Command 0x06: 46 instances (Write Enable)
Command 0x48: 0 instances (Read Security Registers)
Command 0x90: 0 instances (Read Manufacturer/Device ID)
Command 0x0b: 0 instances (Fast Read)
Command 0x42: 0 instances (Program Security Registers)
Command 0x50: 4 instances (Write Enable for Volatile Status Register)
Command 0x33: 0 instances (Read Status Register 3)
Command 0x35: 0 instances (Read Status Register 2)
Command 0x5a: 0 instances (Read Serial Flash Discoverable Parameters (SFDP) Register)
Command 0x9f: 0 instances (Read JEDEC ID)

$ wc -c spiflash_out.bin 
664784 spiflash_out.bin
```
<br>
2)
```
$ python sniffROM.py -o spiflash_out.bin --summary winbond_spiflash_onboot.csv 
Finished parsing input file

Trimming pad bytes...

Rebuilt image: 16777216 bytes (saved to spiflash_out.bin)
Captured data: 7827748 bytes (46.66%) (214 bytes from WRITE commands)

Summary:
Manufacturer ID: 0xef
Device ID: 0x40 0x18
Command 0xab: 0 instances (Read Device ID)
Command 0x01: 0 instances (Write Status Register)
Command 0x02: 3 instances (Page Program)
Command 0x03: 4190 instances (Read Data)
Command 0x04: 3 instances (Write Disable)
Command 0x05: 4232 instances (Read Status Register 1)
Command 0x06: 6 instances (Write Enable)
Command 0x48: 0 instances (Read Security Registers)
Command 0x90: 0 instances (Read Manufacturer/Device ID)
Command 0x0b: 0 instances (Fast Read)
Command 0x42: 0 instances (Program Security Registers)
Command 0x50: 0 instances (Write Enable for Volatile Status Register)
Command 0x33: 0 instances (Read Status Register 3)
Command 0x35: 0 instances (Read Status Register 2)
Command 0x5a: 0 instances (Read Serial Flash Discoverable Parameters (SFDP) Register)
Command 0x9f: 2 instances (Read JEDEC ID)

$ wc -c spiflash_out.bin 
 16777216 spiflash_out.bin
```
Reference: https://www.optiv.com/blog/demystifying-hardware-security-part-ii <br>
JEDEC Manufacturer IDs: http://www.idhw.com/textual/chip/jedec_spd_man.html
