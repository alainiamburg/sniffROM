# sniffROM
Reconstructs flash memory contents from passively captured READ/WRITE commands in a Saleae logic analyzer exported capture file.

Features:
* Preserves memory addresses.
* Currently supports SPI flash chips.
```
usage: sniffROM.py [-h] [--addrlen [{2,3}]] [--endian [{msb,lsb}]]
                   [--filter [{r,w,rw}]] [-o [O]] [--summary] [-v]
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
  -v                    Increase verbosity (up to -vvv)
```
Examples:
Probe a SPI flash chip in a device, and take a Saleae Logic capture during device boot-up. Export SPI analyzer in CSV.

1)
```
$ python sniffROM.py -o spiflash_out.bin --summary spansion_spiflash_onboot.csv
Finished parsing input file
Trimming pad bytes...

Rebuilt image: 664784 bytes (saved to spiflash_out.bin)
Captured data: 234598 bytes (35.29%) (46 bytes from WRITE commands)

Summary:

+---------+-----------+-----------------------------------------------------------+
| Command | Instances | Description                                               |
+---------+-----------+-----------------------------------------------------------+
| 0x01    |         4 | Write Status Register                                     |
| 0x02    |        46 | Page Program                                              |
| 0x03    |     59216 | Read Data                                                 |
| 0x04    |         0 | Write Disable                                             |
| 0x05    |        50 | Read Status Register 1                                    |
| 0x06    |        46 | Write Enable                                              |
| 0x48    |         0 | Read Security Registers                                   |
| 0x0b    |         0 | Fast Read                                                 |
| 0x42    |         0 | Program Security Registers                                |
| 0x50    |         4 | Write Enable for Volatile Status Register                 |
| 0x5a    |         0 | Read Serial Flash Discoverable Parameters (SFDP) Register |
| 0x9f    |         0 | Read JEDEC ID                                             |
| 0x90    |         0 | Read Manufacturer/Device ID                               |
| 0x33    |         0 | Read Status Register 3                                    |
| 0x35    |         0 | Read Status Register 2                                    |
| Unknown |         0 |                                                           |
+---------+-----------+-----------------------------------------------------------+

$ wc -c spiflash_out.bin 
 664784 spiflash_out.bin
```

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

+---------+-----------+-----------------------------------------------------------+
| Command | Instances | Description                                               |
+---------+-----------+-----------------------------------------------------------+
| 0x01    |         0 | Write Status Register                                     |
| 0x02    |         3 | Page Program                                              |
| 0x03    |      4190 | Read Data                                                 |
| 0x04    |         3 | Write Disable                                             |
| 0x05    |      4232 | Read Status Register 1                                    |
| 0x06    |         6 | Write Enable                                              |
| 0x48    |         0 | Read Security Registers                                   |
| 0x0b    |         0 | Fast Read                                                 |
| 0x42    |         0 | Program Security Registers                                |
| 0x50    |         0 | Write Enable for Volatile Status Register                 |
| 0x5a    |         0 | Read Serial Flash Discoverable Parameters (SFDP) Register |
| 0x9f    |         2 | Read JEDEC ID                                             |
| 0x90    |         0 | Read Manufacturer/Device ID                               |
| 0x33    |         0 | Read Status Register 3                                    |
| 0x35    |         0 | Read Status Register 2                                    |
| Unknown |         0 |                                                           |
+---------+-----------+-----------------------------------------------------------+

$ wc -c spiflash_out.bin 
 16777216 spiflash_out.bin
```

Reference: https://www.optiv.com/blog/demystifying-hardware-security-part-ii <br>
JEDEC Manufacturer IDs: http://www.idhw.com/textual/chip/jedec_spd_man.html
