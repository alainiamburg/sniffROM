# sniffROM
Reconstructs flash memory contents from passively captured READ/WRITE commands in a Saleae logic analyzer exported capture file.

Features:
* Preserves memory addresses.
* Data visualization
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
  --graph               Show visual representation of flash layout
  -v                    Increase verbosity (up to -vvv)
```
Examples:
Probe a SPI flash chip in a device, and take a Saleae Logic capture during device boot-up. Export SPI analyzer in CSV.

1) Spansion S25FL116K
```
$ python sniffROM.py -o spiflash_out.bin --summary spansion_spiflash_onboot.csv
Finished parsing input file
Trimming pad bytes...

Rebuilt image: 664784 bytes (saved to spiflash_out.bin)
Captured data: 228847 bytes (34.42%) (46 bytes from WRITE commands)

Summary:

+---------+-----------+-----------------------------------------------------------+
| Command | Instances | Description                                               |
+---------+-----------+-----------------------------------------------------------+
| 0x01    |         4 | Write Status Register 1                                   |
| 0x02    |        46 | Page Program                                              |
| 0x03    |     59216 | Read Data                                                 |
| 0x05    |        50 | Read Status Register 1                                    |
| 0x06    |        46 | Write Enable                                              |
| 0x50    |         4 | Write Enable for Volatile Status Register                 |
+---------+-----------+-----------------------------------------------------------+

$ wc -c spiflash_out.bin 
 664784 spiflash_out.bin
```

2) Winbond W25Q128FV
```
$ python sniffROM.py -o spiflash_out.bin --summary winbond_spiflash_onboot.csv 
Finished parsing input file
Trimming pad bytes...

Rebuilt image: 16777216 bytes (saved to spiflash_out.bin)
Captured data: 6988082 bytes (41.65%) (214 bytes from WRITE commands)

Summary:

Manufacturer ID: 0xef
Device ID: 0x40 0x18

+---------+-----------+-----------------------------------------------------------+
| Command | Instances | Description                                               |
+---------+-----------+-----------------------------------------------------------+
| 0x02    |         3 | Page Program                                              |
| 0x03    |      4190 | Read Data                                                 |
| 0x04    |         3 | Write Disable                                             |
| 0x05    |      4232 | Read Status Register 1                                    |
| 0x06    |         6 | Write Enable                                              |
| 0x9f    |         2 | Read JEDEC ID                                             |
+---------+-----------+-----------------------------------------------------------+

$ wc -c spiflash_out.bin 
 16777216 spiflash_out.bin
```
3) Winbond W25Q64FW (Linksys E800)
```
$ python sniffROM.py -o spiflash_out.bin --summary winbond2_spiflash_onboot.csv
Finished parsing input file
Trimming pad bytes...

Rebuilt image: 8323248 bytes (saved to spiflash_out.bin)
Captured data: 7164937 bytes (86.08%) (0 bytes from WRITE commands)

Summary:

Device ID: 0x16

+---------+-----------+-----------------------------------------------------------+
| Command | Instances | Description                                               |
+---------+-----------+-----------------------------------------------------------+
| 0x0b    |    233844 | Fast Read                                                 |
| 0xab    |         3 | Release Power-Down / Device ID                            |
| 0xb9    |         3 | Power Down                                                |
+---------+-----------+-----------------------------------------------------------+

$ wc -c spiflash_out.bin 
 8323248 spiflash_out.bin
```
4) Spansion S25FL064P (Netgear WNDR3400)
```
$ python sniffROM.py -o spiflash_out.bin spansion2_spiflash_onboot.csv --summary 
Finished parsing input file
Trimming pad bytes...

Rebuilt image: 8346616 bytes (saved to spiflash_out.bin)
Captured data: 3707089 bytes (44.41%) (0 bytes from WRITE commands)

Summary:

Device ID: 0x16

+---------+-----------+-----------------------------------------------------------+
| Command | Instances | Description                                               |
+---------+-----------+-----------------------------------------------------------+
| 0x0b    |   1432193 | Fast Read                                                 |
| 0xab    |         5 | Release Power-Down / Device ID                            |
| 0xb9    |         5 | Power Down                                                |
+---------+-----------+-----------------------------------------------------------+

$ wc -c spiflash_out.bin
 8346616 spiflash_out.bin
```

Reference: https://www.optiv.com/blog/demystifying-hardware-security-part-ii <br>

JEDEC Manufacturer IDs: http://www.idhw.com/textual/chip/jedec_spd_man.html
