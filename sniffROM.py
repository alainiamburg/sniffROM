import argparse, csv, sys

### Logic export csv file format:

#   Time [s], Packet ID, MOSI, MISO
# 0.21347662,         0, 0x05, 0xFF


FLASH_PADDED_SIZE = 20000000     # hacky flash image start size, make this better. auto detect chip size (via JEDEC ID) and adjust accordingly?
FLASH_FILL_BYTE = 0xFF
FLASH_ENDING_SIZE = FLASH_WRITES_ENDING_SIZE = FLASH_PADDED_SIZE

commands = {
	0x01:"Write Status Register",
	0x02:"Page Program",
	0x03:"Read Data",
	0x04:"Write Disable",
	0x05:"Read Status Register 1",
	0x06:"Write Enable",
	0x0B:"Fast Read",
	0x33:"Read Status Register 3",
	0x35:"Read Status Register 2",
	0x42:"Program Security Registers",
	0x48:"Read Security Registers",
	0x50:"Write Enable for Volatile Status Register",
	0x5A:"Read Serial Flash Discoverable Parameters (SFDP) Register",
	0x90:"Read Manufacturer/Device ID",
	0x9F:"Read JEDEC ID",
	0xAB:"Read Device ID"}

command_stats = {
	0x01:0,
	0x02:0,
	0x03:0,
	0x04:0,
	0x05:0,
	0x06:0,
	0x0B:0,
	0x33:0,
	0x35:0,
	0x42:0,
	0x48:0,
	0x50:0,
	0x5A:0,
	0x90:0,
	0x9F:0,
	0xAB:0}	

def dump(data, length, addr):
	hex = lambda line: ' '.join('{:02x}'.format(b) for b in map(ord, line))
	str = lambda line: ''.join(31 < c < 127 and chr(c) or '.' for c in map(ord, line))
	
	for i in range(0, len(data), length):
		line = data[i:i+length]
		print('  0x{:08x}   {:47}   {}'.format(addr+i, hex(line), str(line)))

def print_data(offset):
	if offset <= 4:
		bargraph = "[\033[32;40m*\033[0m-----]"
	elif offset <= 8:
		bargraph = "[\033[32;40m**\033[0m----]"
	elif offset <= 16:
		bargraph = "[\033[33;40m***\033[0m---]"
	elif offset <= 32:
		bargraph = "[\033[33;40m****\033[0m--]"
	elif offset <= 64:
		bargraph = "[\033[31;40m*****\033[0m-]"
	elif offset > 64:
		bargraph = "[\033[31;40m******\033[0m]"
		
	print ' {0} {1} bytes'.format(bargraph, offset)
	dump(str(flash_image[address:address+offset]), 16, address)
						

parser = argparse.ArgumentParser(description="sniffROM - Reconstructs flash memory contents from passively captured READ/WRITE commands in a Saleae logic analyzer exported capture file. Currently supports SPI flash chips.")
parser.add_argument("input_file", help="Saleae Logic SPI Analyzer Export File (.csv)")
parser.add_argument("--addrlen", type=int, choices=[2,3], nargs="?", default=3, help="Length of address in bytes (default is 3)")
parser.add_argument("--endian", choices=["msb", "lsb"], nargs="?", default="msb", help="Endianness of address bytes (default is msb first)")
parser.add_argument("--filter", choices=["r", "w", "rw"], nargs="?", default="rw", help="Parse READ, WRITE, or READ and WRITE commands (default is rw)")
parser.add_argument("-o", nargs="?", default="output.bin", help="Output binary image file (default is output.bin)")
parser.add_argument("--summary", help="Also dump statistics", action="store_true")
parser.add_argument("-v", help="Increase verbosity (up to -vvv)", action="count")
args = parser.parse_args()

flash_image = bytearray([FLASH_FILL_BYTE] * FLASH_PADDED_SIZE)
flash_image_fromWrites = bytearray([FLASH_FILL_BYTE] * FLASH_PADDED_SIZE)
packet_id = -1
new_packet_id = 0
offset = 0
bytes_sniffed = 0
bytes_sniffed_written = 0
unknown_commands = 0


with open(args.input_file, 'rb') as infile:
	packets = csv.reader(infile)
	for packet in packets:
		if packet[1].isdigit():                # ignores the first header line
			packet_time = float(packet[0])
			new_packet_id = int(packet[1],16)
			mosi_data = int(packet[2], 16)
			miso_data = int(packet[3], 16)
			
			if new_packet_id > packet_id:      # IF WE GOT A NEW COMMAND INSTANCE (new Packet ID according to Saleae SPI analyzer)
				packet_id = new_packet_id
				new_command = mosi_data
				if offset > 0:                 # the new packet ID tells us the last command is finished, so dump remaining data from last command, if any
					if args.v > 1:
						print_data(offset)
						offset = 0
				if not (new_command in commands):
					unknown_commands += 1
					if args.v > 1:
						print 'Time: {0:.8f}   Packet ID: {1:5}  Command: 0x{2:02x} - Unknown'.format(packet_time, packet_id, new_command)
				else:
					command = new_command
					command_stats[command] += 1
					if args.v > 0:
						print 'Time: {0:.8f}   Packet ID: {1:5}  Command: 0x{2:02x} - {3}'.format(packet_time, packet_id, command, commands[command])
				if new_command == 0x03:        # New Read command, so reset address and offset in prep for incoming data
					curr_addr_byte = 0
					address_bytes = bytearray([0x00] * args.addrlen)
					offset = 0
				elif new_command == 0x02:      # new page program command
					curr_addr_byte = 0
					address_bytes = bytearray([0x00] * args.addrlen)
					offset = 0
				elif new_command == 0x9f:      # Read ID command
					jedec_id = bytearray([0x00] * 5)   # from 3 to 5
					curr_byte = 0

			elif command == 0x03:              # We are in the middle of a Read command (currently receiving data)
				read_data = miso_data          # the data in a read command comes on MISO
				addr_data = mosi_data
				if (args.filter == 'r' or args.filter == 'rw'):
					if curr_addr_byte == args.addrlen:  # we have the whole address. read data starting with this packet
						if args.endian == "msb":   # TODO add if else for different address byte lengths
							address = (address_bytes[0] << 16) + (address_bytes[1] << 8) + (address_bytes[2] << 0)
						elif args.endian == "lsb":
							address = (address_bytes[2] << 16) + (address_bytes[1] << 8) + (address_bytes[0] << 0)
						if args.v > 2:
							if flash_image[address+offset] != FLASH_FILL_BYTE:    # hacky way to check for multiple access to this addr
								print ' [*] Memory address 0x{:02x} may have been accessed more than once. Perhaps it is important?'.format(address+offset)
						flash_image[address+offset] = read_data
						offset += 1
						bytes_sniffed += 1
					else:   # get the address
						address_bytes[curr_addr_byte] = addr_data
						curr_addr_byte += 1
			elif command == 0x02:	      # we are in a page program (write) command
				write_data = mosi_data    # the data and addr in a write command goes on MOSI
				addr_data = mosi_data
				if (args.filter == 'w' or args.filter == 'rw'):
					if curr_addr_byte == args.addrlen:  # we have the whole address. read data starting with this packet
						if args.endian == "msb":
							address = (address_bytes[0] << 16) + (address_bytes[1] << 8) + (address_bytes[2] << 0)
						elif args.endian == "lsb":
							address = (address_bytes[2] << 16) + (address_bytes[1] << 8) + (address_bytes[0] << 0)
						if args.v > 2:
							if flash_image[address+offset] != FLASH_FILL_BYTE:    # hacky way to check for multiple access to this addr
								print ' [*] Memory address 0x{:02x} may have been accessed more than once. Perhaps it is important?'.format(address+offset)
						flash_image_fromWrites[address+offset] = write_data    # this holds write data separately
						flash_image[address+offset] = write_data
						offset += 1
						bytes_sniffed_written += 1
						bytes_sniffed += 1
					else:   # get the address
						address_bytes[curr_addr_byte] = addr_data
						curr_addr_byte += 1	
			elif command == 0x9f:           # read ID command
				read_data = miso_data
				if curr_byte <= 3:
					jedec_id[curr_byte] = read_data
					curr_byte += 1
				else:
					if args.v > 0:
						print ' [+] Manufacturer ID: {0}'.format(hex(jedec_id[0]))
						print ' [+] Device ID: {0} {1}'.format(hex(jedec_id[1]), hex(jedec_id[2]))
						print ' [+] Look these up here: http://www.idhw.com/textual/chip/jedec_spd_man.html'
	if offset > 0:    # this is here again to catch the very last command. otherwise we leave the for loop without having a chance to print this. kind of ugly.
		if args.v > 1:
			print_data(offset)
			offset = 0

	print 'Finished parsing input file'

# trim extra padding bytes (might lose valid data - if so edit FLASH_FILL_BYTE). this assumes last byte is a padding byte
print '\nTrimming pad bytes...\n'
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
	print '\nSummary:'
	if jedec_id[0]:
		print 'Manufacturer ID: {0}'.format(hex(jedec_id[0]))
		print 'Device ID: {0} {1}'.format(hex(jedec_id[1]), hex(jedec_id[2]))
	for command in command_stats:
		print "Command 0x{0:02x}: {1} instances ({2})".format(command, command_stats[command], commands[command])
	print "Unknown Commands: {0}".format(unknown_commands)
