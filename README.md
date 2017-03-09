# sniffROM
Reconstructs flash memory contents from passively captured READ/WRITE commands in a Saleae logic analyzer exported capture file.

Features:
* Preserves memory addresses.
* Currently supports SPI flash chips.

Example:
Probe a SPI flash chip in a device, and take a Saleae Logic capture during device boot-up. Export SPI analyzer in CSV.
```
$ **python sniffROM.py -o spiflash_out.bin --summary spansion_spiflash_onboot.csv**
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
