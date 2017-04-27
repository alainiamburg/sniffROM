import argparse, csv, sys
import matplotlib
from matplotlib import pyplot
from matplotlib import ticker
#import numpy as np
import datetime

### Logic export csv file formats:

## SPI ##
# Time [s],Packet ID,MOSI,MISO
# 0.21347662,0,0x05,0xFF

## I2C ##
# Time [s],Packet ID,Address,Data,Read/Write,ACK/NAK
# 46.089097500000001,0,0xA0,0x00,Write,ACK
# 46.089121259999999,0,0xA0,0x7A,Write,ACK
# 46.089176700000003,1,0xA1,0xA5,Read,ACK


FLASH_PADDED_SIZE = 20000000     # hacky flash image start size, make this better. auto detect chip size (via JEDEC ID) and adjust accordingly?
FLASH_FILL_BYTE = 0x23
FLASH_ENDING_SIZE = FLASH_WRITES_ENDING_SIZE = FLASH_PADDED_SIZE
GRAPH_BYTES_PER_ROW = 2048

spi_commands = {
#	CMD	DESCRIPTION							R/W	INSTANCES
	0x00: ["No Operation", 							"READ", 	0],
	0x01: ["Write Status Register 1", 					"WRITE", 	0],
	0x02: ["Page Program", 							"WRITE", 	0],
	0x03: ["Read Data", 							"READ", 	0],
	0x04: ["Write Disable", 						"WRITE", 	0],
	0x05: ["Read Status Register 1", 					"READ", 	0],
	0x06: ["Write Enable", 							"WRITE", 	0],
	0x07: ["Read Status Register 2", 					"READ", 	0],
	0x0B: ["Fast Read Data", 						"READ", 	0],
	0x0C: ["Fast Read Data (4-byte address)", 				"READ", 	0],
	0x11: ["Write Status Register 3", 					"WRITE", 	0],
	0x12: ["Page Program (4-byte address)", 				"WRITE", 	0],
	0x13: ["Read Data (4-byte address)", 					"READ", 	0],
	0x14: ["AutoBoot Register Read", 					"READ", 	0],
	0x15: ["AutoBoot Register Write", 					"WRITE", 	0],
	0x16: ["Bank Register Read", 						"READ", 	0],
	0x17: ["Bank Register Write", 						"WRITE", 	0],
	0x20: ["Sector Erase (4K)", 						"WRITE", 	0],
	0x2B: ["Read Security Register", 					"READ", 	0],
	0x2F: ["Program Security Register", 					"WRITE", 	0],
	0x31: ["Write Status Register 2",					"WRITE",	0],
	0x32: ["Page Program (Quad I/O)", 					"WRITE", 	0],
	0x33: ["Read Status Register 3", 					"READ", 	0],
	0x34: ["Page Program (Quad I/O, 4-byte address)", 			"WRITE", 	0],
	0x35: ["Enter QPI Mode", 						"WRITE", 	0],
	0x38: ["Page Program (Quad I/O)", 					"WRITE", 	0],
	0x52: ["Block Erase (32KB)", 						"WRITE", 	0],
	0x42: ["Program Security Register / One Time Program (OTP) array", 	"WRITE", 	0],
	0x48: ["Read Security Register", 					"READ", 	0],
	0x4B: ["Read Unique ID / One Time Program (OTP) Array",			"READ", 	0],
	0x50: ["Write Enable for Volatile Status Register", 			"WRITE", 	0],
	0x5A: ["Read Serial Flash Discoverable Parameters (SFDP) Register",	"READ", 	0],
	0x60: ["Chip Erase", 							"WRITE", 	0],
	0x66: ["Enable Reset", 							"WRITE", 	0],
	0x68: ["Write Protect Selection", 					"WRITE", 	0],
	0xC7: ["Chip Erase", 							"WRITE", 	0],
	0xD8: ["Block Erase (64KB)", 						"WRITE", 	0],
	0x90: ["Read Manufacturer ID / Device ID", 				"READ", 	0],
	0x92: ["Read Manufacturer ID / Device ID (Dual I/O)", 			"READ", 	0],
	0x94: ["Read Manufacturer ID / Device ID (Quad I/O)", 			"READ", 	0],
	0x99: ["Reset Device", 							"WRITE", 	0],
	0x9F: ["Read JEDEC ID", 						"READ", 	0],
	0xAB: ["Release Power-Down / Device ID", 				"READ", 	0],
	0xB9: ["Power Down", 							"WRITE", 	0],
	0xE0: ["Read Dynamic Protection Bit (DYB)", 				"READ", 	0],
	0xE1: ["Write Dynamic Protection Bit (DYB)", 				"WRITE", 	0],
	0xE2: ["Read Persistent Protection Bit (PPB)", 				"READ", 	0],
	0xE3: ["Program Persistent Protection Bit (PPB)", 			"WRITE", 	0],
	0xE4: ["Erase Persistent Protection Bit (PPB)", 			"WRITE", 	0],
	0xE7: ["Password Read", 						"READ", 	0],
	0xE8: ["Password Program", 						"WRITE", 	0],
	0xE9: ["Password Unlock", 						"WRITE", 	0]}
	
def dump(data, length, addr):
	hex = lambda line: ' '.join('{:02x}'.format(b) for b in map(ord, line))
	str = lambda line: ''.join(31 < c < 127 and chr(c) or '.' for c in map(ord, line))
	
	for i in range(0, len(data), length):
		line = data[i:i+length]
		print('  0x{:08x}   {:47}   {}'.format(addr+i, hex(line), str(line)))

def plot_func(x, pos):
	s = '0x%06x' % (int(x)*GRAPH_BYTES_PER_ROW)
	return s

def print_data(data, addr):
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
		
	print ' {0} {1} bytes'.format(bargraph, offset)
	dump(str(data), 16, addr)

def print_new_cmd(command):
	if ((("r" in args.filter) and (spi_commands[command][1] == "READ")) or
		(("w" in args.filter) and (spi_commands[command][1] == "WRITE"))):
		print 'Time: {0:.8f}   Packet ID: {1:5}   Command: 0x{2:02x} - {3}'.format(
				packet_time, packet_id, command, spi_commands[command][0])


flash_image = bytearray([FLASH_FILL_BYTE] * FLASH_PADDED_SIZE)
flash_image_fromWrites = bytearray([FLASH_FILL_BYTE] * FLASH_PADDED_SIZE)
mapping_image = bytearray([0] * FLASH_PADDED_SIZE)
packet_id = -1
new_packet_id = 0
offset = 0
bytes_sniffed = 0                        # this does not count re-reads of same memory addresses
bytes_sniffed_written = 0
unknown_commands = 0
jedec_id = bytearray([0x00] * 5)
device_id = 0x00
i2c_read_addr = 0x00
i2c_write_addr = 0x00


parser = argparse.ArgumentParser(description="sniffROM - Reconstructs flash memory contents and extracts other data from passively sniffed commands in a Saleae logic analyzer capture file. Currently supports SPI and I2C flash chips.")
parser.add_argument("input_file", help="Saleae Logic SPI or I2C Analyzer Export File (.csv)")
parser.add_argument("--addrlen", type=int, choices=[2,3,4], nargs="?", default=3, help="set length of SPI memory address in bytes (default: 3)")
parser.add_argument("--endian", choices=["msb", "lsb"], nargs="?", default="msb", help="set endianness of SPI memory bytes (default: msb)")
parser.add_argument("--filter", choices=["r", "w"], nargs="?", default="rw", help="analyze only READ or WRITE commands (default: both)")
parser.add_argument("-o", nargs="?", default="output.bin", help="flash image output file name (default: output.bin)")
parser.add_argument("--summary", help="print summary of sniffed commands and metadata", action="store_true")
parser.add_argument("--graph", help="show visual representation of flash layout", action="store_true")
parser.add_argument("-v", help="increase verbosity (up to -vvv)", action="count")
args = parser.parse_args()

try:
	infile = open(args.input_file, 'rb')
	packets = csv.reader(infile)
	header = packets.next()
except:
	print 'Failed to open the input file'
	exit()

if header[2] == "MOSI":
	chip_type = "SPI"
	address_bytes = bytearray([0x00] * args.addrlen)
elif header[2] == "Address":
	chip_type = "I2C"
	address_bytes = bytearray([0x00] * 2)
else:
	print 'Unrecognized input file. Exiting.'
	exit()

print "Parsing {0} data...".format(chip_type)
for packet in packets:
	packet_time = float(packet[0])
	new_packet_id = int(packet[1])
	if chip_type == "I2C":
		i2c_addr = int(packet[2], 16)
		sdl_data = int(packet[3], 16)
		new_command = packet[4]
		ack_or_nak = packet[5]
		if new_packet_id > packet_id:
			if offset > 0:
				if args.v > 1:
					print_data(flash_image[address:address+offset], address)
				address = address + offset
				offset = 0
			packet_id = new_packet_id
			curr_addr_byte = 0
		if new_command == "Write":
			addr_byte = sdl_data         # assume writing start addr for subsequent read cmd
			i2c_write_addr = i2c_addr
			address_bytes[curr_addr_byte] = addr_byte
			if curr_addr_byte == 1:
				address = (address_bytes[0] << 8) + (address_bytes[1])
				if args.v > 0:
					print 'Time: {0:.8f}   Packet ID: {1:5}   Read Data @ 0x{2:02x}'.format(
							packet_time, packet_id, address)
			else:
				curr_addr_byte += 1
		elif new_command == "Read":
			read_byte = sdl_data
			i2c_read_addr = i2c_addr
			if flash_image[address+offset] != FLASH_FILL_BYTE:
				if args.v > 2:
					print ' [*] Memory address 0x{:02x} was accessed more than once.'.format(
								address+offset)
			else:
				bytes_sniffed += 1
			flash_image[address+offset] = read_byte
			if mapping_image[address+offset] != 2:
				mapping_image[address+offset] = 1
			offset += 1
	elif chip_type == "SPI":
		mosi_data = int(packet[2], 16)
		miso_data = int(packet[3], 16)
		if new_packet_id > packet_id:    # IF WE GOT A NEW COMMAND INSTANCE (new Packet ID according to Saleae SPI analyzer)
			if offset > 0:               # the new packet ID tells us the last command is finished,
				if args.v > 1:           # so dump remaining data from last command, if any
					print_data(flash_image[address:address+offset], address)
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
					print 'Time: {0:.8f}   Packet ID: {1:5}   Command: 0x{2:02x} - Unknown'.format(
							packet_time, packet_id, new_command)
			else:
				command = new_command
				spi_commands[command][2] += 1
				if args.v > 0:
					print_new_cmd(command)
		elif ((command == 0x03) or       # Read
			  (command == 0x0b)):        # Fast Read
			if "r" in args.filter:
				read_byte = miso_data    # the data in a read command comes on MISO
				addr_byte = mosi_data
				if curr_addr_byte == args.addrlen:  # we have the whole address. read data
					if (command == 0x0b) and (dummy_byte_fastread == True):
						dummy_byte_fastread = False     # Fast Read command sends a dummy byte (8 clock cycles) after the address
					else:
						if args.endian == "msb":   # TODO add if else for different address byte lengths
							address = (address_bytes[0] << 16) + (address_bytes[1] << 8) + (address_bytes[2] << 0)
						elif args.endian == "lsb":
							address = (address_bytes[2] << 16) + (address_bytes[1] << 8) + (address_bytes[0] << 0)

						if flash_image[address+offset] != FLASH_FILL_BYTE:    # hacky way to check for multiple access to this addr
							if args.v > 2:
								print ' [*] Memory address 0x{:02x} was accessed more than once.'.format(
											address+offset)
						else:
							bytes_sniffed += 1
						flash_image[address+offset] = read_byte
						if mapping_image[address+offset] != 2:
							mapping_image[address+offset] = 1
						offset += 1
				else:   # get the address
					address_bytes[curr_addr_byte] = addr_byte
					curr_addr_byte += 1
		elif command == 0x02:	         # Page Program (Write)
			if "w" in args.filter:
				write_byte = mosi_data   # the data and addr in a write command goes on MOSI
				addr_byte = mosi_data
				if curr_addr_byte == args.addrlen:   # we have the whole address. read data
					if args.endian == "msb":
						address = (address_bytes[0] << 16) + (address_bytes[1] << 8) + (address_bytes[2] << 0)
					elif args.endian == "lsb":
						address = (address_bytes[2] << 16) + (address_bytes[1] << 8) + (address_bytes[0] << 0)

					if flash_image[address+offset] != FLASH_FILL_BYTE:    # hacky way to check for multiple access to this addr
						if args.v > 2:
							print ' [*] Memory address 0x{:02x} was accessed more than once.'.format(
										address+offset)
					else:
						bytes_sniffed += 1
					flash_image_fromWrites[address+offset] = write_byte    # holds write data separately
					flash_image[address+offset] = write_byte
					bytes_sniffed_written += 1
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
					print ' [+] Device ID: {0}'.format(hex(device_id))
			else:
				dummy_bytes_rpddid += 1
		elif command == 0x9f:            # read JEDEC ID (1 byte MFG ID, and 1-3 byte Device ID)
			read_byte = miso_data
			if curr_id_byte <= 3:
				jedec_id[curr_id_byte] = read_byte
				curr_id_byte += 1
			else:
				if args.v > 0:
					print ' [+] Manufacturer ID: {0}'.format(hex(jedec_id[0]))
					print ' [+] Device ID: {0} {1}'.format(hex(jedec_id[1]), hex(jedec_id[2]))
		elif (command == 0x01 or      # Write Status Register 1
			  command == 0x05):       # Read Status Register 1
			write_byte = mosi_data if command == 0x01 else miso_data
			SR1 = write_byte
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
				print '  |                 Status Register 1 = 0x{:02x}                 |'.format(SR1)
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
				if args.v > 2:
					print '  +----------------------------------------------------------+'
					print '  |       Write Protection: {0}        |'.format(SRP)
					print '  +---------+---------------------+---------+----------------+'
					print '  |  Block  | Addresses           | Density | Portion        |'
					print '  +---------+---------------------+---------+----------------+'
					if BP2:
						if BP1:
							if BP0:
								print '  |   0-127  | 0x000000 - 0x7FFFFF |    8MB  | ALL            |'
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
								print '  |   NONE  |        NONE         |   NONE  |      NONE      |'
					print '  +---------+---------------------+---------+----------------+'
if offset > 0:
	if args.v > 1:
		print_data(flash_image[address:address+offset], address+offset)
		offset = 0
print 'Finished parsing input file'
print 'Trimming pad bytes...\n'          # trim extra padding bytes (might lose valid data - if so edit FLASH_FILL_BYTE). this assumes last byte is a padding byte
while ((flash_image[FLASH_ENDING_SIZE-1] == FLASH_FILL_BYTE) and (FLASH_ENDING_SIZE > 0)):
	FLASH_ENDING_SIZE -= 1
while ((flash_image_fromWrites[FLASH_WRITES_ENDING_SIZE-1] == FLASH_FILL_BYTE) and (FLASH_WRITES_ENDING_SIZE > 0)):
	FLASH_WRITES_ENDING_SIZE -= 1
try:
	with open(args.o, 'wb') as outfile:
		outfile.write(flash_image[0:FLASH_ENDING_SIZE])
	with open('out_write.bin', 'wb') as outfile:
		outfile.write(flash_image_fromWrites[0:FLASH_WRITES_ENDING_SIZE])
except:
	print 'Failed to write the output file'
print 'Rebuilt image: {0} bytes (saved to {1})\nCaptured data: {2} bytes ({3:.2f}%) ({4} bytes from WRITE commands)'.format(
		FLASH_ENDING_SIZE, args.o, bytes_sniffed, ((bytes_sniffed / float(FLASH_ENDING_SIZE)) * 100.0), bytes_sniffed_written)

if args.summary:
	print '\nSummary:\n'
	if jedec_id[0]:
		print 'Manufacturer ID: {0}'.format(hex(jedec_id[0]))
		print 'Device ID: {0} {1}\n'.format(hex(jedec_id[1]), hex(jedec_id[2]))
	if device_id:
		print 'Device ID: {0}\n'.format(hex(device_id))
	if i2c_read_addr:
		print 'I2C Read Address: {0}'.format(hex(i2c_read_addr))
	if i2c_write_addr:
		print 'I2C Write Address: {0}\n'.format(hex(i2c_write_addr))
	if chip_type == "SPI":	
		print '+---------+-----------+-----------------------------------------------------------+'
		print '| Command | Instances | Description                                               |'
		print '+---------+-----------+-----------------------------------------------------------+'
		for command in spi_commands:
			if spi_commands[command][2] > 0:
				print "| 0x{0:02x}    | {1:9} | {2:57} |".format(command, spi_commands[command][2], spi_commands[command][0])
		if unknown_commands > 0:
			print "| Unknown | {0:9} |                                                           |".format(unknown_commands)
		print '+---------+-----------+-----------------------------------------------------------+'

if args.graph:
	print '\nGenerating Graph...'
	if chip_type == "I2C":
		GRAPH_BYTES_PER_ROW = 512
	mapping_bytes = []
	mapping_rows = FLASH_ENDING_SIZE / GRAPH_BYTES_PER_ROW
	mapping_remainder = FLASH_ENDING_SIZE % GRAPH_BYTES_PER_ROW
	
	for row in range(0,mapping_rows):
		mapping_bytes.append(mapping_image[row*GRAPH_BYTES_PER_ROW:(row*GRAPH_BYTES_PER_ROW)+GRAPH_BYTES_PER_ROW])	

	cmap = matplotlib.colors.ListedColormap(['black', 'blue', 'red'])
	bounds=[1,1,2,2]
	norm = matplotlib.colors.BoundaryNorm(bounds, ncolors=3)
	fig = pyplot.figure()
	#fig.canvas.set_window_title('Flash Layout - {0} [{1}]'.format(args.o, args.input_file[args.input_file.rfind("/")+1:]))
	fig.canvas.set_window_title('Flash Layout - {0} [{1}]'.format(args.o, args.input_file))
	pyplot.imshow(mapping_bytes, interpolation='nearest', cmap=cmap, norm=norm, aspect='auto')
	#pyplot.colorbar()
	pyplot.ylabel('Address')
	pyplot.xlabel('Offset')
	pyplot.grid(True, color='white')
	#pyplot.title('Flash Layout')
	axes = pyplot.gca()
	axes.get_xaxis().set_major_formatter(ticker.FormatStrFormatter("0x%04x"))
	axes.get_yaxis().set_major_formatter(ticker.FuncFormatter(plot_func))
	pyplot.savefig('{:%Y%m%d_%H%M%S}.png'.format(datetime.datetime.now()), dpi=fig.dpi, bbox_inches='tight')
	pyplot.show()