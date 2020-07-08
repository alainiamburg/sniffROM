import argparse, csv, sys
import matplotlib
#matplotlib.use('Agg')  # This is needed if no X windows server
#from matplotlib import pyplot
import matplotlib.pyplot as plt
from matplotlib import ticker

### Logic export csv file formats:

## SPI ##
# Time [s],Packet ID,MOSI,MISO
# 0.21347662,0,0x05,0xFF

## I2C ##
# Time [s],Packet ID,Address,Data,Read/Write,ACK/NAK
# 46.089097500000001,0,0xA0,0x00,Write,ACK
# 46.089121259999999,0,0xA0,0x7A,Write,ACK
# 46.089176700000003,1,0xA1,0xA5,Read,ACK


FLASH_PADDED_SIZE = 40000000     # hacky flash image start size, make this better. auto detect chip size (via JEDEC ID) and adjust accordingly?
FLASH_FILL_BYTE = 0x23
FLASH_ENDING_SIZE = FLASH_WRITES_ENDING_SIZE = FLASH_PADDED_SIZE
GRAPH_BYTES_PER_ROW = 2048
MINOR_GRAPH_BYTES_PER_ROW = 512
INVALID_DATA = -1

chip_vendors = {
#       MFR ID  NAME
        0x01:  "Cypress/Spansion",
        0x1C:  "Eon",
        0x1F:  "Atmel",
        0x20:  "Micron/Numonyx",
        0xBF:  "Microchip/SST",
        0xC2:  "Macronix",
        0xC8:  "GigaDevice",
        0xEF:  "Winbond",
        0xF8:  "Fidelix"
}
# TODO integrate https://github.com/flashrom/flashrom/blob/staging/flashchips.h

spi_commands = {
#       CMD     DESCRIPTION                                                     R/W     INSTANCES
        0x00: ["No Operation",                                                  "Read",         0],
        0x01: ["Write Status Register 1",                                       "Write",        0],
        0x02: ["Page Program",                                                  "Write",        0],
        0x03: ["Read Data",                                                     "Read",         0],
        0x04: ["Write Disable",                                                 "Write",        0],
        0x05: ["Read Status Register 1",                                        "Read",         0],
        0x06: ["Write Enable",                                                  "Write",        0],
        0x07: ["Read Status Register 2 [Spansion]",                             "Read",         0],
        0x0B: ["Fast Read Data",                                                "Read",         0],
        0x0C: ["Fast Read Data (4-byte address)",                               "Read",         0],
        0x11: ["Write Status Register 3",                                       "Write",        0],
        0x12: ["Page Program (4-byte address)",                                 "Write",        0],
        0x13: ["Read Data (4-byte address)",                                    "Read",         0],
        0x14: ["Read AutoBoot Register [Spansion]",                             "Read",         0],
        0x15: ["Write AutoBoot Register / Read Status Register 3",              "Write",        0],
        0x16: ["Bank Register Read",                                            "Read",         0],
        0x17: ["Write Fast Boot Register",                                      "Write",        0],
        0x18: ["Erase Fast Boot Register",                                      "Write",        0],
        0x1B: ["Fast Read Data [Atmel]",                                        "Read",         0],
        0x20: ["Sector Erase (4K)",                                             "Write",        0],
        0x21: ["Sector Erase (4K) (4-byte address)",                            "Write",        0],
        0x27: ["Read Password Register [Macronix]",                             "Read",         0],
        0x28: ["Write Password Register [Macronix]",                            "Write",        0],
        0x29: ["Password Unlock [Macronix]",                                    "Write",        0],
        0x2B: ["Read Security Register",                                        "Read",         0],
        0x2C: ["Write Lock Register [Macronix]",                                "Write",        0],
        0x2D: ["Read Lock Register [Macronix]",                                 "Read",         0],
        0x2F: ["Write Security Register",                                       "Write",        0],
        0x30: ["Clear/Reset Fail Flags / Resume Program",                       "Write",        0],
        0x31: ["Write Status Register 2",                                       "Write",        0],
        0x32: ["Page Program (Quad I/O)",                                       "Write",        0],
        0x33: ["Read Status Register 3",                                        "Read",         0],
        0x34: ["Page Program (Quad I/O, 4-byte address)",                       "Write",        0],
        0x35: ["Read Status Register 2",                                        "Read",         0],
        0x36: ["Single Block Lock/Protect",                                     "Write",        0],
        0x38: ["Page Program (Quad I/O)",                                       "Write",        0],
        0x39: ["Single Block Unlock/Unprotect",                                 "Write",        0],
        0x3A: ["Enter OTP Mode",                                                "Write",        0],
        0x3B: ["Read Data (Dual I/O)",                                          "Read",         0],
        0x3C: ["Read Data (Dual I/O) (4-byte address)",                         "Read",         0],
        0x3D: ["Read Block Lock",                                               "Read",         0],
        0x3E: ["Page Program (Quad I/O) (4-byte address)",                      "Write",        0],
        0x40: ["Sector Erase (2x 4K) [Spansion]",                               "Write",        0],
        0x41: ["Read Data Learning Register [Spansion]",                        "Read",         0],
        0x42: ["Program Security Register / One Time Program (OTP) array",      "Write",        0],
        0x43: ["Program Non-Volatile Data Learning Register",                   "Write",        0],
        0x44: ["Erase Security Register / One Time Program (OTP) array",        "Write",        0],
        0x45: ["Exit x8 Parallel Mode [Spansion]",                              "Write",        0],
        0x48: ["Read Security Register",                                        "Read",         0],
        0x4A: ["Write Volatile Data Learning Register",                         "Write",        0],
        0x4B: ["Read Unique ID / One Time Program (OTP) Array",                 "Read",         0],
        0x50: ["Write Enable for Volatile Status Register",                     "Write",        0],
        0x52: ["Block Erase (32KB)",                                            "Write",        0],
        0x55: ["Enter x8 Parallel Mode [Spansion]",                             "Write",        0],
        0x5A: ["Read Serial Flash Discoverable Parameters (SFDP) Register",     "Read",         0],
        0x60: ["Chip Erase",                                                    "Write",        0],
        0x61: ["Write Volatile Enhanced Configuration Register",                "Write",        0],
        0x65: ["Read Volatile Enhanced Configuration Register",                 "Read",         0],
        0x66: ["Enable Reset",                                                  "Write",        0],
        0x68: ["Write Protect Selection",                                       "Write",        0],
        0x6B: ["Read Data (Quad I/O)",                                          "Read",         0],
        0x6C: ["Read Data (Quad I/O) (4-byte address)",                         "Read",         0],
        0x70: ["Enable SO to Output RY/BY# During CP Mode",                     "Write",        0],
        0x75: ["Erase / Program Suspend",                                       "Write",        0],
        0x77: ["Set Burst With Wrap",                                           "Write",        0],
        0x7A: ["Erase / Program Resume",                                        "Write",        0],
        0x7E: ["Enable Write Protection (Whole Chip)",                          "Write",        0],
        0x80: ["Disable SO to Output RY/BY# During CP Mode",                    "Write",        0],
        0x81: ["Write Volatile Configuration Register",                         "Write",        0],
        0x85: ["Read Volatile Configuration Register / Program Suspend",        "Read",         0],
        0x88: ["Read Security ID [SST]",                                        "Read",         0],
        0x8A: ["Program Resume [Spansion]",                                     "Write",        0],
        0x8C: ["Burst Read Data with Wrap for Lower 128Mb",                     "Read",         0],
        0x8D: ["Burst Read Data with Wrap for Higher 128Mb",                    "Read",         0],
        0x90: ["Read Manufacturer ID / Device ID",                              "Read",         0],
        0x92: ["Read Manufacturer ID / Device ID (Dual I/O)",                   "Read",         0],
        0x94: ["Read Manufacturer ID / Device ID (Quad I/O)",                   "Read",         0],
        0x98: ["Disable Write Protection (Whole Chip)",                         "Write",        0],
        0x99: ["Reset Device",                                                  "Write",        0],
        0x9B: ["Program OTP Security Register [Atmel]",                         "Write",        0],
        0x9F: ["Read JEDEC ID",                                                 "Read",         0],
        0xA2: ["Page Program (Dual Input)",                                     "Write",        0],
        0xA3: ["Enable High Performance Mode (Quad I/O)",                       "Write",        0],
        0xA5: ["Program User Security ID",                                      "Write",        0],
        0xA6: ["Lock Bit Write",                                                "Write",        0],
        0xA7: ["Lock Bit Read",                                                 "Read",         0],
        0xAA: ["Enable HOLD# Pin Functionality of RST#/HOLD# Pin",              "Write",        0],
        0xAB: ["Release Power-Down / Device ID",                                "Read",         0],
        0xAD: ["Continuously Program (CP) Mode",                                "Write",        0],
        0xAF: ["Read ID (QPI Mode)",                                            "Read",         0],
        0xB0: ["Suspend Program/Erase",                                         "Write",        0],
        0xB1: ["Enter Secured OTP Mode / Write NV Configuration Register",      "Write",        0],
        0xB5: ["Read NV Configuration Register",                                "Read",         0],
        0xB7: ["Enter 4-byte Mode",                                             "Write",        0],
        0xB9: ["Power Down",                                                    "Write",        0],
        0xBB: ["Read Data (2x I/O)",                                            "Read",         0],
        0xBC: ["Read Data (2x I/O) (4-byte address)",                           "Read",         0],
        0xBD: ["Read Data (Dual I/O) (Double Transfer Rate)",                   "Read",         0],
        0xC0: ["Set Burst Length / Set Read Parameters",                        "Write",        0],
        0xC1: ["Exit Secured OTP Mode",                                         "Write",        0],
        0xC5: ["Write Extended Address Register",                               "Write",        0],
        0xC7: ["Chip Erase",                                                    "Write",        0],
        0xC8: ["Read Extended Address Register",                                "Read",         0],
        0xCF: ["Read MFG ID / Device ID (4x I/O) (Double Transfer Rate)",       "Read",         0],
        0xD0: ["Resume Program/Erase [Atmel]",                                  "Write",        0],
        0xD2: ["Extended Fast Program (Dual Input) [Numonyx]",                  "Write",        0],
        0xD8: ["Block Erase (64/256KB)",                                        "Write",        0],
        0xDC: ["Block Erase (64/256KB) (4-byte address)",                       "Write",        0],
        0xDF: ["Read MFG ID / Device ID (4x I/O)",                              "Read",         0],
        0xE0: ["Read Dynamic Protection Bit (DYB)",                             "Read",         0],
        0xE1: ["Write Dynamic Protection Bit (DYB)",                            "Write",        0],
        0xE2: ["Read Persistent Protection Bit (PPB)",                          "Read",         0],
        0xE3: ["Program Persistent Protection Bit (PPB)",                       "Write",        0],
        0xE4: ["Erase Persistent Protection Bit (PPB)",                         "Write",        0],
        0xE5: ["Write Lock Register [Numonyx]",                                 "Write",        0],
        0xE6: ["Reserved [Spansion]",                                           "Read",         0],
        0xE7: ["Password Read",                                                 "Read",         0],
        0xE8: ["Password Program [Spansion] / Read Lock Register [Numonyx]",    "Write",        0],
        0xE9: ["Password Unlock / Exit 4-byte Mode [Macronix]",                 "Write",        0],
        0xEA: ["Read Data (Quad I/O) from top 128Mb",                           "Read",         0],
        0xEB: ["Read Data (Quad I/O) from bottom 128Mb",                        "Read",         0],
        0xEC: ["Read Data (Quad I/O) (4-byte address)",                         "Read",         0],
        0xED: ["Read Data (Dual I/O) (Quad Transfer Rate)",                     "Read",         0],
        0xEF: ["Read MFG ID / Device ID (2x I/O)",                              "Read",         0],
        0xF0: ["Reset [Atmel/Spansion]",                                        "Write",        0],
        0xF5: ["Exit QPI Mode [Macronix]",                                      "Write",        0],
        0xFF: ["Mode Bit Reset / Exit QPI Mode",                                "Write",        0]}

def dump(data, length, addr):
    hex = lambda line: ' '.join('{:02x}'.format(b) for b in map(ord, line))
    str = lambda line: ''.join(31 < c < 127 and chr(c) or '.' for c in map(ord, line))

    for i in range(0, len(data), length):
        line = data[i:i+length]
        print('  0x{:08x}   {:47}   {}'.format(addr+i, hex(line), str(line)))
    print ""

def plot_func(x, pos):
    s = '0x%06x' % (int(x)*GRAPH_BYTES_PER_ROW)
    return s

def plot_func_minor(x, pos):
    s = '0x%06x' % (int(x)*MINOR_GRAPH_BYTES_PER_ROW)
    return s

def print_data(data, addr, access_type):
    if offset <= 4:
        bargraph = "[\033[32;49m*\033[0m-----]"
    elif offset <= 8:
        bargraph = "[\033[32;49m**\033[0m----]"
    elif offset <= 16:
        bargraph = "[\033[33;49m***\033[0m---]"
    elif offset <= 32:
        bargraph = "[\033[33;49m****\033[0m--]"
    elif offset <= 64:
        bargraph = "[\033[31;49m*****\033[0m-]"
    elif offset > 64:
        bargraph = "[\033[31;49m******\033[0m]"

    #if args.colors:
    #    print ' {0} {1} {2} bytes'.format(bargraph, access_type, offset)
    #else:
    #    print ' {0} {1} bytes'.format(access_type, offset)
    print ' {0} {1} bytes'.format(access_type, offset)
    dump(str(data), 16, addr)

def print_new_cmd(command):
    if ((("r" in args.filter) and (spi_commands[command][1] == "Read")) or
            (("w" in args.filter) and (spi_commands[command][1] == "Write"))):
        print 'Time: {0:.8f}   Packet ID: {1:7}   Command: 0x{2:02X} - {3}'.format(
                        packet_time, packet_id, command, spi_commands[command][0])

def bytes_to_addr(bytes):
    if args.endian == "msb":
        if args.addrlen == 4:
            address = (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3]
        elif args.addrlen == 3:
            address = (bytes[0] << 16) + (bytes[1] << 8) + bytes[2]
        elif args.addrlen == 2:
            address = (bytes[0] << 8) + bytes[1]
    elif args.endian == "lsb":
        if args.addrlen == 4:
            address = (bytes[3] << 24) + (bytes[2] << 16) + (bytes[1] << 8) + bytes[0]
        elif args.addrlen == 3:
            address = (bytes[2] << 16) + (bytes[1] << 8) + bytes[0]
        elif args.addrlen == 2:
            address = (bytes[1] << 8) + bytes[0]
    return address

def decode_spi_dualio(io0_byte, io1_byte):
    read_bytes = 0
    bitcnt = 0
    while bitcnt < 16:
        if bitcnt & 1:
            read_bytes |= ((io1_byte & 1) << bitcnt)
            io1_byte >>= 1
        else:
            read_bytes |= ((io0_byte & 1) << bitcnt)
            io0_byte >>= 1
        bitcnt += 1
    return ((read_bytes >> 8) & 0xFF), read_bytes & 0xFF



parser = argparse.ArgumentParser(description="sniffROM - Reconstructs flash memory contents and extracts other data from passively sniffed commands in a Saleae logic analyzer capture file. Currently supports SPI and I2C flash chips.")
parser.add_argument("input_file", help="Saleae Logic SPI or I2C Analyzer Export File (.csv)")
parser.add_argument("--addrlen", type=int, choices=[2,3,4], nargs="?", default=3, help="set length of SPI memory address in bytes (default: 3)")
parser.add_argument("--endian", choices=["msb", "lsb"], nargs="?", default="msb", help="set endianness of SPI memory bytes (default: msb)")
parser.add_argument("--filter", choices=["r", "w"], nargs="?", default="rw", help="analyze only Read or Write commands (default: both)")
parser.add_argument("-o", nargs="?", default="output.bin", help="flash image output file name (default: output.bin)")
parser.add_argument("--summary", help="print summary of sniffed commands and metadata", action="store_true")
#parser.add_argument("--colors", help="output color codes", action="store_true")
parser.add_argument("--data-map", help="show visual data map", action="store_true")
parser.add_argument("--timing-plot", help="show timing analysis", action="store_true")
parser.add_argument("-v", help="increase verbosity (up to -vvv)", action="count")
args = parser.parse_args()

flash_image = bytearray([FLASH_FILL_BYTE] * FLASH_PADDED_SIZE)
flash_image_fromWrites = bytearray([FLASH_FILL_BYTE] * FLASH_PADDED_SIZE)
sfdp_image = bytearray([FLASH_FILL_BYTE] * FLASH_PADDED_SIZE)
sfdp_address = 0
sfdp_offset = 0
mapping_image = bytearray([0] * FLASH_PADDED_SIZE)

#timing mapping stuff
map_timing_addresses = []   #we consider each instance of an address as a 'time tick' as well
map_timing_addresses_writes = []

repeat_access_image = bytearray([0] * FLASH_PADDED_SIZE)
packet_id = -1
new_packet_id = 0
offset = 0
bytes_sniffed = 0                        # this does not count re-reads of same memory addresses
bytes_sniffed_written = 0
highest_byte = 0
unknown_commands = 0
jedec_id = bytearray([0x00] * 5)
EN4B = False
device_id = 0x00
i2c_read_addr = 0x00
i2c_write_addr = 0x00
i2c_reads = 0
i2c_writes = 0



try:
    infile = open(args.input_file, 'rb')
    packets = csv.reader(infile)
    header = packets.next()
except:
    print 'Failed to open the input file'
    exit()

if header[2] == "MOSI":
    chip_type = "SPI"
    address_bytes = bytearray([0x00] * 4)
    #address_bytes = bytearray([0x00] * args.addrlen)
elif header[2] == "Address":
    chip_type = "I2C"
    address_bytes = bytearray([0x00] * 2)
else:
    print 'Unrecognized input file. Exiting.'
    exit()

print "Parsing {0} data...\n".format(chip_type)
for packet in packets:
    packet_time = float(packet[0])
    if packet[1] != '':
        new_packet_id = int(packet[1])
    else:
        new_packet_id = INVALID_DATA
    if chip_type == "I2C":
        i2c_addr = int(packet[2], 16)
        if packet[3] != '':
            sdl_data = int(packet[3], 16)
        else:
            sdl_data = INVALID_DATA
        new_command = packet[4]
        ack_or_nak = packet[5]
        if new_packet_id == INVALID_DATA or new_packet_id > packet_id:
            if offset > 0:
                if write_byte != INVALID_DATA and read_byte == INVALID_DATA:
                    i2c_writes += 1
                    if args.v > 1:
                        print_data(flash_image_fromWrites[address:address+offset], address, "Write")
                elif write_byte == INVALID_DATA and read_byte != INVALID_DATA:
                    i2c_reads += 1
                    if args.v > 1:
                        print_data(flash_image[address:address+offset], address, "Read")
                address = address + offset
                offset = 0
            curr_addr_byte = 0
            read_byte = INVALID_DATA
            write_byte = INVALID_DATA
            if new_packet_id == INVALID_DATA:
                print 'Time: {0:.8f}   Packet ID:         Skip Packet (missing ID)'.format(packet_time)
                continue
            else:
                packet_id = new_packet_id
        if new_command == "Write":
            if curr_addr_byte != 2:
                addr_byte = sdl_data         # assume writing start addr for subsequent read cmd
                i2c_write_addr = i2c_addr
                address_bytes[curr_addr_byte] = addr_byte
                if curr_addr_byte == 1:
                    address = (address_bytes[0] << 8) + (address_bytes[1])
                    if args.v > 0:
                        print 'Time: {0:.8f}   Packet ID: {1:7}   Access Data @ 0x{2:02x}'.format(
                                        packet_time, packet_id, address)
                curr_addr_byte += 1
            else:
                write_byte = sdl_data
                i2c_write_addr = i2c_addr
                flash_image_fromWrites[address+offset] = write_byte    # holds write data separately
                highest_byte = (address+offset) if highest_byte < (address+offset) else highest_byte
                bytes_sniffed_written += 1
                if mapping_image[address+offset] == 1:
                    mapping_image[address+offset] = 3
                else:
                    mapping_image[address+offset] = 2
                offset += 1
        elif new_command == "Read":
            read_byte = sdl_data
            i2c_read_addr = i2c_addr
            if flash_image[address+offset] != FLASH_FILL_BYTE:
                if args.v > 2:
                    print ' [*] Repeated access to memory @ 0x{:02x}'.format(
                                            address+offset)
            else:
                bytes_sniffed += 1
            flash_image[address+offset] = read_byte
            highest_byte = (address+offset) if highest_byte < (address+offset) else highest_byte
            if mapping_image[address+offset] == 2:
                mapping_image[address+offset] = 3
            else:
                mapping_image[address+offset] = 1
            offset += 1
    elif chip_type == "SPI":
        mosi_data = int(packet[2], 16)
        miso_data = int(packet[3], 16)
        if new_packet_id > packet_id:    # IF WE GOT A NEW COMMAND INSTANCE (new Packet ID according to Saleae SPI analyzer)
            if offset > 0:               # the new packet ID tells us the last command is finished,
                if args.v > 1:           # so dump remaining data from last command, if any
                    print_data(flash_image[address:address+offset], address, spi_commands[command][1])
                    offset = 0
            packet_id = new_packet_id
            new_command = mosi_data
            curr_id_byte = 0
            curr_addr_byte = 0
            offset = 0
            dummy_byte_fastread = True
            dummy_bytes_rpddid = 0
            if not (new_command in spi_commands):
                unknown_commands += 1
                command = -1
                if args.v > 0:
                    print 'Time: {0:.8f}   Packet ID: {1:7}   Command: 0x{2:02X} - Unknown'.format(
                                    packet_time, packet_id, new_command)
            else:
                command = new_command
                spi_commands[command][2] += 1
                if args.v > 0:
                    print_new_cmd(command)
            if command == 0xb7:           # Enable 4-byte address mode
                orig_addrlen = args.addrlen
                args.addrlen = 4
                EN4B = True
                if args.v > 1:
                    print " [*] Address length changed from {0} to {1} bytes".format(orig_addrlen, args.addrlen)
            elif command == 0xe9:
                if EN4B == True:                        # Disable 4-byte address mode
                    args.addrlen = orig_addrlen
                    if args.v > 1:
                        print " [*] Address length changed from 4 to {0} bytes".format(orig_addrlen)
                    EN4B = False
        elif ((command == 0x03) or       # Read
              (command == 0x0b) or       # Fast Read
              (command == 0x0c) or       # Fast Read 4-bytes address mode
              (command == 0xbb) or       # Read Data (2x I/O)
              (command == 0x3b)):        # Fast Read Dual Output
            if "r" in args.filter:
                if (command == 0x0c and curr_addr_byte == 4) or (command != 0x0c and curr_addr_byte == args.addrlen):  # we have the whole address. read data
                    if (command == 0x0b or command == 0x0c or command == 0x3b) and (dummy_byte_fastread == True):
                        dummy_byte_fastread = False     # Fast Read command sends a dummy byte (8 clock cycles) after the address
                    else:
                        address = bytes_to_addr(address_bytes)
                        if flash_image[address+offset] != FLASH_FILL_BYTE:    # hacky way to check for multiple access to this addr
                            if args.v > 2:
                                print ' [*] Repeated access to memory @ 0x{:02x}'.format(address+offset)
                        else:
                            bytes_sniffed += 1
                        if command == 0x3b or command == 0xbb:
                            # the data in a read command comes in MOSI and MISO
                            read_byte1, read_byte2 = decode_spi_dualio(mosi_data, miso_data);

                            # save first byte
                            flash_image[address+offset] = read_byte1
                            highest_byte = (address+offset) if highest_byte < (address+offset) else highest_byte
                            map_timing_addresses.append(address+offset)
                            if mapping_image[address+offset] == 2:
                                mapping_image[address+offset] = 3
                            else:
                                mapping_image[address+offset] = 1
                            offset += 1

                            if flash_image[address+offset] != FLASH_FILL_BYTE:    # hacky way to check for multiple access to this addr
                                if args.v > 2:
                                    print ' [*] Repeated access to memory @ 0x{:02x}'.format(address+offset)

                            # save second byte
                            flash_image[address+offset] = read_byte2
                            highest_byte = (address+offset) if highest_byte < (address+offset) else highest_byte
                            map_timing_addresses.append(address+offset)
                            if mapping_image[address+offset] == 2:
                                mapping_image[address+offset] = 3
                            else:
                                mapping_image[address+offset] = 1
                            offset += 1
                        else:
                            read_byte = miso_data    # the data in a read command comes on MISO
                            flash_image[address+offset] = read_byte
                            highest_byte = (address+offset) if highest_byte < (address+offset) else highest_byte
                            map_timing_addresses.append(address+offset)
                            if mapping_image[address+offset] == 2:
                                mapping_image[address+offset] = 3
                            else:
                                mapping_image[address+offset] = 1
                            offset += 1
                else:   # get the address
                    if command == 0xbb: # 2x I/O means addr use miso and mosi as well
                        read_byte1, read_byte2 = decode_spi_dualio(mosi_data, miso_data)
                        address_bytes[curr_addr_byte] = read_byte1
                        curr_addr_byte += 1
                        if (curr_addr_byte < args.addrlen):
                            address_bytes[curr_addr_byte] = read_byte2
                            curr_addr_byte += 1
                    else:
                        address_bytes[curr_addr_byte] = mosi_data
                        curr_addr_byte += 1
        elif command == 0x02:            # Page Program (Write)
            if "w" in args.filter:
                write_byte = mosi_data   # the data and addr in a write command goes on MOSI
                addr_byte = mosi_data
                if curr_addr_byte == args.addrlen:   # we have the whole address. read data
                    address = bytes_to_addr(address_bytes)

                    if flash_image[address+offset] != FLASH_FILL_BYTE:    # hacky way to check for multiple access to this addr
                        if args.v > 2:
                            print ' [*] Repeated access to memory @ 0x{:02x}'.format(
                                                    address+offset)
                    else:
                        bytes_sniffed += 1
                    flash_image_fromWrites[address+offset] = write_byte    # holds write data separately
                    flash_image[address+offset] = write_byte
                    highest_byte = (address+offset) if highest_byte < (address+offset) else highest_byte
                    map_timing_addresses_writes.append(address+offset)
                    bytes_sniffed_written += 1
                    if mapping_image[address+offset] == 1:
                        mapping_image[address+offset] = 3
                    else:
                        mapping_image[address+offset] = 2
                    offset += 1
                else:                    # get the address
                    address_bytes[curr_addr_byte] = addr_byte
                    curr_addr_byte += 1
        elif command == 0xab:            # Release Power-Down / Device ID
            read_byte = miso_data
            if dummy_bytes_rpddid == 3:    # If this command is followed by 3 dummy bytes,
                device_id = read_byte      #  then it is a Device ID command
                if args.v > 0:
                    print ' [+] Device ID: 0x{0:02X}'.format(int(device_id))
            else:
                dummy_bytes_rpddid += 1
        elif command == 0x9f:            # read JEDEC ID (1 byte MFG ID, and 1-3 byte Device ID)
            read_byte = miso_data
            if curr_id_byte <= 3:
                jedec_id[curr_id_byte] = read_byte
                curr_id_byte += 1
            else:
                if args.v > 0:
                    print ' [+] Manufacturer ID: 0x{0:02X}'.format(int(jedec_id[0]))
                    print ' [+] Device ID: 0x{0:02X}{1:02X}'.format(int(jedec_id[1]), int(jedec_id[2]))
        elif (command == 0x01 or      # Write Status Register 1
                command == 0x05):       # Read Status Register 1
            sr_byte = mosi_data if command == 0x01 else miso_data
            SR1 = sr_byte
            SR1 = sr_byte
            SRP1 = 0                # TODO handle an optional Reg 2 read byte, which contains SRP1
            SRP0 = SR1 & (1 << 7)
            SEC = SR1 & (1 << 6)
            TB = SR1 & (1 << 5)
            BP2 = SR1 & (1 << 4)
            BP1 = SR1 & (1 << 3)
            BP0 = SR1 & (1 << 2)
            WEL = SR1 & (1 << 1)
            BUSY = SR1 & (1 << 0)
            BP_SIZE = "4KB Sectors" if SEC else "64KB Blocks"
            TOP_BOTTOM = "From Bottom of Array" if TB else "From Top of Array"
            if SRP1:
                if SRP0:
                    SRP = "One Time Program"
                else:
                    SRP = "Power Supply Lock-Down"
            else:
                if SRP0:
                    SRP = "Hardware Controlled (/WP)"
                else:
                    SRP = "Software Controlled (WEL)"

            if args.v > 1:
                print '  +----------------------------------------------------------+'
                print '  |                                                          |'
                print '  |                Status Register 1 = 0x{:02X}                  |'.format(SR1)
                print '  |                                                          |'
                print '  +-----+------+-------------------------------+-------------+'
                print '  | Bit | Name | Description                   | Value       |'
                print '  +-----+------+-------------------------------+-------------+'
                print '  |  7  | SRP0 | Status Register Protect 0     | {:d}           |'.format(1 if SRP0 else 0)
                print '  |  6  | SEC  | Sector Protect Bit            | {:d}           |'.format(1 if SEC else 0)
                print '  |  5  | TB   | Top/Bottom Protect Bit        | {:d}           |'.format(1 if TB else 0)
                print '  |  4  | BP2  | Block Protect Bit 2           | {:d}           |'.format(1 if BP2 else 0)
                print '  |  3  | BP1  | Block Protect Bit 1           | {:d}           |'.format(1 if BP1 else 0)
                print '  |  2  | BP0  | Block Protect Bit 0           | {:d}           |'.format(1 if BP0 else 0)
                print '  |  1  | WEL  | Write Enable Latch            | {:d}           |'.format(1 if WEL else 0)
                print '  |  0  | BUSY | Erase/Write In Progress       | {:d}           |'.format(1 if BUSY else 0)
                print '  +-----+------+-------------------------------+-------------+'
                print '  |                                                          |'
                print '  |       Write Protection: {0}        |'.format(SRP)
                print '  |                                                          |'
                print '  +---------+---------------------+---------+----------------+'
                print '  |  Block  | Addresses           | Density | Portion        |'
                print '  +---------+---------------------+---------+----------------+'
                if BP2:
                    if BP1:
                        if BP0:
                            print '  |   0-127  | 0x000000 - 0x7FFFFF |    8MB  |   ALL          |'
                        else:
                            if TB:
                                print '  |   0-63  | 0x000000 - 0x3FFFFF |    4MB  |   Lower 1/2    |'
                            else:
                                print '  |  64-127 | 0x400000 - 0x7FFFFF |    4MB  |   Upper 1/2    |'
                    else:
                        if BP0:
                            if SEC:
                                if TB:
                                    print '  |    0   | 0x000000 - 0x007FFF |   32KB  |   Lower 1/256  |'
                                else:
                                    print '  |   127  | 0x7F8000 - 0x7FFFFF |   32KB  |   Upper 1/256  |'
                            else:
                                if TB:
                                    print '  |   0-31  | 0x000000 - 0x1FFFFF |    2MB  |   Lower 1/4    |'
                                else:
                                    print '  |  96-127 | 0x000000 - 0x7FFFFF |    2MB  |   Upper 1/4    |'
                        else:
                            if BP1:
                                if BP0:
                                    if SEC:
                                        if TB:
                                            print '  |     0    | 0x000000 - 0x003FFF |   16KB  |  Lower 1/512   |'
                                        else:
                                            print '  |    127   | 0x7FC000 - 0x7FFFFF |   16KB  |  Upper 1/512   |'
                                    else:
                                        if TB:
                                            print '  |   0-7    | 0x000000 - 0x7FFFFF |  512KB  |  Lower 1/16    |'
                                        else:
                                            print '  | 120-127  | 0x780000 - 0x7FFFFF |  512KB  |  Upper 1/16    |'
                                else:
                                    if SEC:
                                        if TB:
                                            print '  |    0    | 0x000000 - 0x001FFF |    8KB  |  Lower 1/1024  |'
                                        else:
                                            print '  |   127   | 0x7FE000 - 0x7FFFFF |    8KB  |  Upper 1/1024  |'
                                    else:
                                        if TB:
                                            print '  |   0-3   | 0x000000 - 0x3FFFFF |  256KB  |   Lower 1/32   |'
                                        else:
                                            print '  | 124-127 | 0x7C0000 - 0x7FFFFF |  256KB  |   Upper 1/32   |'
                            else:
                                if BP0:
                                    if SEC:
                                        if TB:
                                            print '  |    0   | 0x000000 - 0x000FFF |    4KB  |  Lower 1/2048  |'
                                        else:
                                            print '  |   127  | 0x7FF000 - 0x7FFFFF |    4KB  |  Upper 1/2048  |'
                                    else:
                                        if TB:
                                            print '  |   0-1   | 0x000000 - 0x1FFFFF |  128KB  |   Lower 1/64   |'
                                        else:
                                            print '  | 126-127 | 0x7E0000 - 0x7FFFFF |  128KB  |   Upper 1/64   |'
                else:
                    print '  |   ---   |        -----        |   ---   |      ----      |'
                print '  +---------+---------------------+---------+----------------+'
                print ''


if offset > 0:
    if args.v > 1:
        if chip_type == "I2C":
            if write_byte != INVALID_DATA and read_byte == INVALID_DATA:
                print_data(flash_image_fromWrites[address:address+offset], address, "Write")
            elif write_byte == INVALID_DATA and read_byte != INVALID_DATA:
                print_data(flash_image[address:address+offset], address, "Read")
        else:
            print_data(flash_image[address:address+offset], address, spi_commands[command][1])
        offset = 0
#print 'Finished parsing input file'
#print 'Trimming pad bytes...\n'          # trim extra padding bytes (might lose valid data - if so edit FLASH_FILL_BYTE). this assumes last byte is a padding byte
#while ((flash_image[FLASH_ENDING_SIZE-1] == FLASH_FILL_BYTE) and (FLASH_ENDING_SIZE > 0)):
#    FLASH_ENDING_SIZE -= 1
#while ((flash_image_fromWrites[FLASH_WRITES_ENDING_SIZE-1] == FLASH_FILL_BYTE) and (FLASH_WRITES_ENDING_SIZE > 0)):
#    FLASH_WRITES_ENDING_SIZE -= 1
try:
    with open(args.o, 'wb') as outfile:
        outfile.write(flash_image[0:highest_byte+1])
    #with open('out_write.bin', 'wb') as outfile:
    #       outfile.write(flash_image_fromWrites[0:FLASH_WRITES_ENDING_SIZE])
except:
    print 'Failed to write the output file'
#print 'Rebuilt image: {0} bytes (saved to {1})\nCaptured data: {2} bytes ({3:.2f}%) ({4} bytes from Write commands)'.format(
#                FLASH_ENDING_SIZE, args.o, bytes_sniffed, ((bytes_sniffed / float(FLASH_ENDING_SIZE)) * 100.0), bytes_sniffed_written)
print 'Rebuilt image: {0} bytes (saved to {1})\nCaptured data: {2} bytes ({3:.2f}%) ({4} bytes from Write commands)'.format(
                highest_byte+1, args.o, bytes_sniffed, ((bytes_sniffed / float(highest_byte)) * 100.0), bytes_sniffed_written)



if args.summary:
    print '\nSummary:\n'
    if jedec_id[0]:
        print 'Mfr. ID: 0x{0:02X} ({1})'.format(int(jedec_id[0]), chip_vendors.get(jedec_id[0], "Unknown"))
        print 'Device ID: 0x{0:02X}{1:02X}\n'.format(int(jedec_id[1]), int(jedec_id[2]))
    if device_id:
        print 'Device ID: 0x{0:02X}\n'.format(int(device_id))
    if chip_type == "SPI":
        print '+------+-----------+-----------------------------------------------------------+'
        print '| Cmd  | Instances | Description                                               |'
        print '+------+-----------+-----------------------------------------------------------+'
        for command in spi_commands:
            if spi_commands[command][2] > 0:
                print "| 0x{0:02X} | {1:9} | {2:57} |".format(command, spi_commands[command][2], spi_commands[command][0])
        if unknown_commands > 0:
            print "| Unk. | {0:9} | Unknown Command / Error in Capture                        |".format(unknown_commands)
        print '+------+-----------+-----------------------------------------------------------+'
    elif chip_type == "I2C":
        print '+------+-----------+-----------+'
        print '| Addr | Instances | Operation |'
        print '+------+-----------+-----------+'
        print "| 0x{0:02X} | {1:9} | Read      |".format(i2c_read_addr, i2c_reads)
        print "| 0x{0:02X} | {1:9} | Write     |".format(i2c_write_addr, i2c_writes)
        print '+------+-----------+-----------+'
    print ''


if args.data_map:
    print 'Generating data map...'
    if chip_type == "I2C":
        GRAPH_BYTES_PER_ROW = 512
    mapping_bytes = []
    #mapping_rows = FLASH_ENDING_SIZE / GRAPH_BYTES_PER_ROW
    #mapping_remainder = FLASH_ENDING_SIZE % GRAPH_BYTES_PER_ROW
    mapping_rows = highest_byte / GRAPH_BYTES_PER_ROW
    mapping_remainder = highest_byte % GRAPH_BYTES_PER_ROW

    for row in range(0,mapping_rows):
        mapping_bytes.append(mapping_image[row*GRAPH_BYTES_PER_ROW:(row*GRAPH_BYTES_PER_ROW)+GRAPH_BYTES_PER_ROW])

    cmap = matplotlib.colors.ListedColormap(['black', 'blue', 'red', 'purple'])
    bounds=[-1,0.5,1.1,2.1,3.1]
    norm = matplotlib.colors.BoundaryNorm(bounds, cmap.N)
    fig = plt.figure()
    fig.canvas.set_window_title('Data Map - {0} [{1}]'.format(args.o, args.input_file[args.input_file.rfind("/")+1:]))
    plt.imshow(mapping_bytes, interpolation='nearest', cmap=cmap, norm=norm, aspect='auto')
    #plt.colorbar()
    plt.ylabel('Base Address')
    plt.xlabel('Offset')
    plt.grid(True, color='white', linewidth=1)
    plt.title('Captured Data')
    axes = plt.gca()
    axes.get_xaxis().set_major_formatter(ticker.FormatStrFormatter("0x%04x"))
    axes.get_yaxis().set_major_formatter(ticker.FuncFormatter(plot_func))
    axes.get_yaxis().set_minor_formatter(ticker.FuncFormatter(plot_func_minor))
    plt.show()

if args.timing_plot:
    print 'Generating timing plot...'
    x_axis = [tick for tick in range(0,len(map_timing_addresses))]
    y_axis = map_timing_addresses
    #plt.rcParams['axes.facecolor'] = 'black'   # black background
    plt.plot(x_axis, y_axis, 'bo')

    # overlay writes on top of reads
    x_axis = [tick for tick in range(0,len(map_timing_addresses_writes))]
    y_axis = map_timing_addresses_writes
    #plt.rcParams['axes.facecolor'] = 'black'   # black background

    plt.plot(x_axis, y_axis, 'ro')

    if map_timing_addresses:
        plt.axis([0, len(map_timing_addresses), 0, len(map_timing_addresses)])
    else:
        plt.axis([0, len(map_timing_addresses_writes), 0, len(map_timing_addresses_writes)])

    axes = plt.gca()
    axes.invert_yaxis()
    axes.get_yaxis().set_major_formatter(ticker.FormatStrFormatter("0x%04x"))
    #fig.canvas.set_window_title('Timing Analysis - {0}'.format(args.input_file[args.input_file.rfind("/")+1:]))
    plt.title('Timing Analysis')
    plt.ylabel('Address')
    plt.xlabel('Time Ticks')
    plt.show()
