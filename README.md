# sniffROM
A tool for passive data capture and reconnaissance of flash chips. It is used in conjunction with a Saleae logic analyzer to reconstruct flash memory contents and extract contextual information about device operations.

* Supports SPI and I²C flash chips.
* Recognizes most flash commands across different chip vendors.
* Preserves actual memory addresses of captured data.
* Binary visualization of reconstructed image.
```
usage: sniffROM.py [-h] [--addrlen [{2,3}]] [--endian [{msb,lsb}]]
                   [--filter [{r,w,rw}]] [-o [O]] [--summary] [-v]
                   input_file

positional arguments:
  input_file            Saleae Logic SPI/I2C Analyzer Export File (.csv)

optional arguments:
  -h, --help            show this help message and exit
  --addrlen [{2,3}]     Length of address in bytes (default is 3)
  --endian [{msb,lsb}]  Endianness of address bytes (default is msb first)
  --filter [{r,w,rw}]   Parse READ, WRITE, or READ and WRITE commands (default is rw)
  -o [O]                Output binary image file (default is output.bin)
  --summary             Also dump statistics
  --graph               Show visual representation of flash layout
  -v                    Increase verbosity (up to -vvv)
```
See [Wiki](https://github.com/alainiamburg/sniffROM/wiki) for documentation
