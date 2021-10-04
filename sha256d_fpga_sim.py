#########################################################################
# Richie Harris
# rkharris12@gmail.com
# 5/23/2021
#########################################################################

# simulation of the FPGA implementation of sha256d

import hashlib
import binascii


# utility functions
def reverse_byte_order(hex_str): # reverse the order of bytes in a hex string
    return ''.join([ hex_str[2 * i: 2 * i + 2] for i in list(range(0, len(hex_str) // 2))[::-1] ])

def reverse_word_order(hex_str): # reverse the order of 32 bit words in a hex string
    return ''.join([ hex_str[8 * i: 8 * i + 8] for i in list(range(0, len(hex_str) // 8))[::-1] ])

def pad(msg_hex_str):
	"""takes in a hex string representing the hash input, pads it to nearest 512 bit boundary, appends input size"""
	# find pad size
	msg_len = len(msg_hex_str)*4 # need the length in bits, not hex chars
	padded_str = msg_hex_str
	padded_str += "8" # add the 1 bit "1" separator between original message and zero pad
	pad_len = 512 # in bits
	while pad_len < len(padded_str)*4 + 64:
		pad_len += 512

	pad_len = pad_len//4 # convert bits to hex chars

	# zero pad
	for i in list(range(len(padded_str), pad_len - 64//4)): # 64 bits at the end encodes message size
		padded_str += "0"
    
	# append encoded message size in last 64 bits
	msg_len_str = hex(msg_len)[2:]
	extra_pad_len = 64//4 - len(msg_len_str)
	for i in list(range(extra_pad_len)):
		padded_str += "0"
	padded_str += msg_len_str

	return padded_str

# python simulation of the FPGA hasher
k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,\
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,\
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,\
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,\
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,\
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,\
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,\
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

def idx(x, y):
	return (x >> (y * 32)) & 0xFFFFFFFF

def ror(x, y):
	return (x >> y) | ((x << (32 - y)) & 0xFFFFFFFF)

def round(a, b, c, d, e, f, g, h, data, k):
	w14 = idx(data, 14)
	w9 = idx(data, 9)
	w1 = idx(data, 1)
	w0 = idx(data, 0)
	s0 = ror(w1, 7) ^ ror(w1, 18) ^ (w1 >> 3)
	s1 = ror(w14, 17) ^ ror(w14, 19) ^ (w14 >> 10)
	w16 = (w0 + s0 + s1 + w9) & 0xFFFFFFFF

	data = (data >> 32) | (w16 << 480)

	e0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)
	e1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)
	maj = (a & b) ^ (a & c) ^ (b & c)
	ch = (e & f) ^ ((~e) & g)

	t2 = (e0 + maj) & 0xFFFFFFFF
	t1 = (h + e1 + ch + k + w0) & 0xFFFFFFFF

	h = g
	g = f
	f = e
	e = (d + t1) & 0xFFFFFFFF
	d = c
	c = b
	b = a
	a = (t1 + t2) & 0xFFFFFFFF
	
	return (a, b, c, d, e, f, g, h, data)

def hash(state, data):
	a = idx(state, 0)
	b = idx(state, 1)
	c = idx(state, 2)
	d = idx(state, 3)
	e = idx(state, 4)
	f = idx(state, 5)
	g = idx(state, 6)
	h = idx(state, 7)

	for i in range(64):
		(a, b, c, d, e, f, g, h, data) = round(a, b, c, d, e, f, g, h, data, k[i])

		#print "\t[%d]\t\t%08x%08x%08x%08x%08x%08x%08x%08x" % (i, h, g, f, e, d, c, b, a)
	
	a = (a + idx(state, 0)) & 0xFFFFFFFF
	b = (b + idx(state, 1)) & 0xFFFFFFFF
	c = (c + idx(state, 2)) & 0xFFFFFFFF
	d = (d + idx(state, 3)) & 0xFFFFFFFF
	e = (e + idx(state, 4)) & 0xFFFFFFFF
	f = (f + idx(state, 5)) & 0xFFFFFFFF
	g = (g + idx(state, 6)) & 0xFFFFFFFF
	h = (h + idx(state, 7)) & 0xFFFFFFFF
	
	return (h << 224) | (g << 192) | (f << 160) | (e << 128) | (d << 96) | (c << 64) | (b << 32) | a

if __name__ == "__main__":
	# bitcoin block 123,456: test input - 80 bytes, 640 bits, already flipped to network byte order
	#network_in = "010000009500c43a25c624520b5100adf82cb9f9da72fd2447a496bc600b0000000000006cd862370395dedf1da2841ccda0fc489e3039de5f1ccddef0e834991a65600ea6c8cb4db3936a1ae3143991"
	# test output (in true byte order)
	#test_out = 0x0000000000002917ed80650c6174aac8dfc46f5fe36480aaef682ff6cd83c3ca
	#mid_state <= X"74b4c79dbf5de76d0815e94b0d66604341602d39063461d5faf888259fd47d57";
    #residual_data <= X"b3936a1aa6c8cb4d1a65600e";
    #target <= X"0000000000006a93b30000000000000000000000000000000000000000000000";


	# block header fields in big endian hex strings
	version = "00000001"
	prev_block_hash = "0000000000000b60bc96a44724fd72daf9b92cf8ad00510b5224c6253ac40095"
	merkle_root = "0e60651a9934e8f0decd1c5fde39309e48fca0cd1c84a21ddfde95033762d86c"
	time = "4dcbc8a6"
	bits = "1a6a93b3"
	golden_nonce = 2436437219
	nonce_counter = golden_nonce - 5 # exercise the code a little
	nonce = hex(nonce_counter).rstrip("L").lstrip("0x")

	# convert to little endian and concatenate to form block header - block header is 80 bytes = 640 bits
	block_header = reverse_byte_order(version) + reverse_byte_order(prev_block_hash) + reverse_byte_order(merkle_root) + reverse_byte_order(time) + reverse_byte_order(bits) + reverse_byte_order(nonce)
	
	target_hex = "0000000000006a93b30000000000000000000000000000000000000000000000"
	target = int(target_hex, 16)

	# iterate until golden nonce is found
	while (True):
		print("nonce          : %s" % hex(nonce_counter).rstrip("L"))

		# use library function to compute double sha256 hash for validation
		sha256_lib_in = bytes.fromhex(block_header)
		sha256_lib_out = hashlib.sha256(hashlib.sha256(sha256_lib_in).digest()).hexdigest()
		#print("lib function network byte order: 0x%s" % sha256_lib_out)
		print("hashlib result : 0x%s" % reverse_byte_order(sha256_lib_out))

		# FPGA hash simulator
		state_init = 0x5be0cd191f83d9ab9b05688c510e527fa54ff53a3c6ef372bb67ae856a09e667 # initial state of state registers in hash function
		message_blocks = pad(block_header)
		# hash first 512 bit message block
		first_block = reverse_word_order(message_blocks[0:(512//4)]) # reverse word ordering for hash function
		data_in = int(first_block, 16) # convert from hex string to numerical data
		mid_state = hash(state_init, data_in)

		# hash second 512 bit message_block
		second_block = reverse_word_order(message_blocks[(512//4):(1024//4)]) # reverse word ordering for hash function
		data_in = int(second_block, 16) # convert from hex string to numerical data
		hash_1 = hash(mid_state, data_in)
		hash_1_word_rev = reverse_word_order(hex(hash_1).rstrip("L").lstrip("0x")) # put it back into big endian word order for padding function
		# hash a second time
		padded_in_2 = pad(hash_1_word_rev)
		block = reverse_word_order(padded_in_2) # reverse word ordering for hash function
		data_in = int(block, 16) # convert from hex string to numerical data
		hash_2 = hash(state_init, data_in)
		hash_2_word_rev = reverse_word_order(hex(hash_2).rstrip("L").lstrip("0x")) # put it back into big endian word order
		while len(hash_2_word_rev) < 64:
			hash_2_word_rev = hash_2_word_rev + "0"
		hash_2_result = reverse_byte_order(hash_2_word_rev) # convert back to big endian byte order before comparing to target
		print("sha256d result : 0x%s" % hash_2_result)
		#print("target:        : %s" % hex(target).rstrip("L"))
		print("target:        : %s" % ("0x" + target_hex))

		# compare hash result to target
		if int(hash_2_result, 16) < target:
			print("golden nonce found!")
			break

		# increment nonce
		nonce_counter = nonce_counter + 1
		nonce = hex(nonce_counter).rstrip("L").lstrip("0x")
		block_header = block_header[0:-8] + reverse_byte_order(nonce)
		print("")
