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
See [Wiki](https://github.com/alainiamburg/sniffROM/wiki) for documentation

Reference: https://www.optiv.com/blog/demystifying-hardware-security-part-ii <br>

JEDEC Manufacturer IDs: http://www.idhw.com/textual/chip/jedec_spd_man.html
