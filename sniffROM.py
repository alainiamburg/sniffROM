import argparse, csv, sys

### Logic export csv file format:
#   Time [s], Packet ID, MOSI, MISO
# 0.21347662,         0, 0x05, 0xFF

# TODO
# -add warning when a sniffed memory address is accessed more than once (read or write)
# -support multiple address lengths (SPI_ADDRLEN)
# -parse device ID data
# -support more commands
# -allow filtering by command



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
		print(' {:08x}   {:47}   {}'.format(addr+i, hex(line), str(line)))


def print_data():
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
	offset = 0
						

FLASH_PADDED_SIZE = 20000000     # hacky flash image start size, make this better. auto detect chip size (via JEDEC ID) and adjust accordingly?
FLASH_FILL_BYTE = 0xFF
FLASH_ENDING_SIZE = FLASH_WRITES_ENDING_SIZE = FLASH_PADDED_SIZE


# parser = argparse.ArgumentParser(prog='PROG', usage='%(prog)s [options]')
parser = argparse.ArgumentParser(description="sniffROM - Reconstructs flash memory contents from passively captured READ/WRITE commands in a Saleae logic analyzer exported capture file. Currently supports SPI flash chips.")
parser.add_argument("input_file", help="Saleae Logic SPI Analyzer Export File (.csv)")
parser.add_argument("--addrlen", type=int, choices=[2,3], nargs="?", default=3, help="Length of address in bytes (default is 3)")
parser.add_argument("--endian", choices=["msb", "lsb"], nargs="?", default="msb", help="Endianness of address bytes (default is msb first)")
parser.add_argument("--filter", choices=["r", "w", "rw"], nargs="?", default="rw", help="Parse READ, WRITE, or READ and WRITE commands (default is rw)")
parser.add_argument("-o", nargs="?", default="output.bin", help="Output binary image file (default is output.bin)")
parser.add_argument("--summary", help="Also dump statistics", action="store_true")
parser.add_argument("--verbose", "-v", help="Increase verbosity", action="count")
args = parser.parse_args()

flash_image = bytearray([FLASH_FILL_BYTE] * FLASH_PADDED_SIZE)
flash_image_fromWrites = bytearray([FLASH_FILL_BYTE] * FLASH_PADDED_SIZE)
curr_packet_id = -1
new_packet_id = 0
offset = 0
bytes_sniffed = 0
bytes_sniffed_written = 0
unknown_commands = 0


with open(args.input_file, 'rb') as infile:
	reader = csv.reader(infile)
	for row in reader:
		#print row
		#print '{0} {1} {2} {3}'.format(row[0], row[1], row[2], row[3])
		if row[1].isdigit():   # ignores the first header line
			new_pkt_id = int(row[1],16)
			mosi_data = int(row[2], 16)
			miso_data = int(row[3], 16)
			
			if new_pkt_id > curr_packet_id:    # IF WE GOT A NEW COMMAND INSTANCE (new Packet ID according to Saleae SPI analyzer)
				#print 'old pkt id was {0} and new pkt id is {1}'.format(curr_packet_id, new_pkt_id)
				# the new packet ID means the last command is finished, and now we know the last read is finished so dump it
				if offset > 0:
					if args.verbose > 1:
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
						
						#print ' {0} {1} bytes @ {2}'.format(bargraph, offset, hex(address))
						print ' {0} {1} bytes'.format(bargraph, offset)
						dump(str(flash_image[address:address+offset]), 16, address)
						offset = 0
				
						
				curr_packet_id = new_pkt_id
				command = mosi_data
				if not (command in commands):
					unknown_commands += 1
				else:
					command_stats[command] += 1
				
				if command == 0x03:   # New Read command, so reset address and offset in prep for incoming data
					curr_addr_byte = 0
					address_bytes = bytearray([0x00] * args.addrlen)
					offset = 0
				elif command == 0x02:  #new page program command
					curr_addr_byte = 0
					address_bytes = bytearray([0x00] * args.addrlen)
					offset = 0
				elif command == 0x9f:   # Read ID command
					device_id = bytearray([0x00] * 3)
					curr_byte = 0
				
				if command in commands:
					if args.verbose > 0:
						print 'Time: {0:.9}   Packet ID: {1:5}  Command: {2} - {3}'.format(row[0], row[1], row[2], commands[command])
				else:
					if args.verbose > 1:
						print 'Time: {0:.9}   Packet ID: {1:5}  Command: {2} - Unknown'.format(row[0], row[1], row[2])
						
						
			elif command == 0x03:        # We are in the middle of a Read command (currently receiving data)
				miso_data = int(row[3], 16)    # the data in a read command comes on MISO
				mosi_data = int(row[2], 16)
				if (args.filter == 'r' or args.filter == 'rw'):
					if curr_addr_byte == args.addrlen:  # we have the whole address. read data starting with this row
						if args.endian == "msb":   # TODO add if else for different address byte lengths
							address = (address_bytes[0] << 16) + (address_bytes[1] << 8) + (address_bytes[2] << 0)
						elif args.endian == "lsb":
							address = (address_bytes[2] << 16) + (address_bytes[1] << 8) + (address_bytes[0] << 0)
						flash_image[address+offset] = miso_data
						offset += 1
						bytes_sniffed += 1
					else:   # get the address
						#print 'curr_addr_byte is {0}'.format(curr_addr_byte)
						address_bytes[curr_addr_byte] = mosi_data
						curr_addr_byte += 1
			elif command == 0x02:	# we are in a page (write) command
				mosi_data = int(row[2], 16)   # the data in a write command goes on MOSI
				if (args.filter == 'w' or args.filter == 'rw'):
					if curr_addr_byte == args.addrlen:  # we have the whole address. read data starting with this row
						if args.endian == "msb":
							address = (address_bytes[0] << 16) + (address_bytes[1] << 8) + (address_bytes[2] << 0)
						elif args.endian == "lsb":
							address = (address_bytes[2] << 16) + (address_bytes[1] << 8) + (address_bytes[0] << 0)
						flash_image_fromWrites[address+offset] = mosi_data
						flash_image[address+offset] = mosi_data
						offset += 1
						bytes_sniffed_written += 1
						bytes_sniffed += 1
					else:   # get the address
						#print 'curr_addr_byte is {0}'.format(curr_addr_byte)
						address_bytes[curr_addr_byte] = mosi_data
						curr_addr_byte += 1	
			elif command == 0x9f:  # read ID command
				miso_data = int(row[3], 16)
				if curr_byte <= 2:
					device_id[curr_byte] = miso_data
					curr_byte += 1
				else:
					if args.verbose > 0:
						print '[+] Manufacturer ID: {0}'.format(hex(device_id[0]))
						print '[+] Device ID: {0} {1}'.format(hex(device_id[1]), hex(device_id[2]))
						print '[+] Look these up here: http://www.idhw.com/textual/chip/jedec_spd_man.html'
	
	# this is here again to catch the very last command. otherwise we leave the for
	# loop without having a chance to print this. kind of ugly. turn this into a function?
	if offset > 0:
		if args.verbose > 1:
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
			#print ' {0} {1:06} bytes @ {2}'.format(bargraph, offset, hex(address))
			print ' {0} {1} bytes'.format(bargraph, offset)
			dump(str(flash_image[address:address+offset]), 16, address)
			offset = 0

	print 'Finished parsing input file'

			


# trim extra padding bytes (might lose valid data - if so edit FLASH_FILL_BYTE)
# this assumes last byte is a padding byte
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


print 'Rebuilt image: {0} bytes (saved to {1})\nCaptured data: {2} bytes ({3:.2f}%) ({4} bytes from WRITE commands)'.format(FLASH_ENDING_SIZE, args.o, bytes_sniffed, ((bytes_sniffed / float(FLASH_ENDING_SIZE)) * 100.0), bytes_sniffed_written)


if args.summary:
	print '\nSummary:'
	if device_id[0]:
		print 'Manufacturer ID: {0}'.format(hex(device_id[0]))
		print 'Device ID: {0} {1}'.format(hex(device_id[1]), hex(device_id[2]))
	for command in command_stats:
		print "Command 0x{0:02x}: {1} instances ({2})".format(command, command_stats[command], commands[command])
	print "Unknown Commands: {0}".format(unknown_commands)
