import hashlib
import struct
from secp256k1 import PrivateKey, PublicKey


def ripemd160(data):
	ret = hashlib.new('ripemd160')
	ret.update(hashlib.sha256(data).digest())
	return ret.digest()


def sha256d(data):
	return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def header_serialize(header):
	"""Serialize header data to raw bytes"""
	return (struct.pack("<L", header['version']) +
						bytearray.fromhex(header['prev_block'])[::-1] +
						bytearray.fromhex(header['merkle_root'])[::-1] +
						struct.pack("<LLL", header['timestamp'], header['bits'], header['nonce']) +
						bytearray.fromhex(header['miner_pubkey'])[::-1])


def header_deserialize(raw_header):
	"""Deserialize raw bytes to header data"""
	return {
		'version': struct.unpack("<L", raw_header[:4])[0],
		'prev_block': raw_header[4:36][::-1].hex(),
		'merkle_root': raw_header[36:68][::-1].hex(),
		'timestamp': struct.unpack("<L", raw_header[68:72])[0],
		'bits': struct.unpack("<L", raw_header[72:76])[0],
		'nonce': struct.unpack("<L", raw_header[76:80])[0],
		'miner_pubkey': raw_header[80:113][::-1].hex()
	}


def validate_target(header_hash, bits):
	"""Validate PoW target"""
	target = ('%064x' % ((bits & 0xffffff) * (1 << (8 * ((bits >> 24) - 3))))).split('f')[0]
	zeros = len(target)
	return header_hash[::-1].hex()[:zeros] == target


def validate_signature(sighash, signature, miner_pubkey):
	"""Validate header signature"""
	pubkey = PublicKey(miner_pubkey, raw=True)
	return pubkey.ecdsa_verify(sighash, pubkey.ecdsa_deserialize(signature))


def miner(header, privkey):
	"""Simple miner implementation, not very eficient but good enough :)"""
	while header['nonce'] < 0x100000000:
		# Serialize header data
		raw_header = header_serialize(header)
		# Get ripemd160 hash of header
		sighash = ripemd160(raw_header)
		# Sign ripemd160 hash with out private key
		signature = privkey.ecdsa_serialize(privkey.ecdsa_sign(sighash))[::-1]

		header_hash = sha256d(raw_header + signature)
		if validate_target(header_hash, header['bits']):
			return raw_header, signature

		header['nonce'] += 1


def main():
	# Generate keypair which we will use for signing block header
	privkey = PrivateKey()
	pubkey = privkey.pubkey

	print('Private key: {}'.format(privkey.serialize()))
	print('Public key: {}'.format(pubkey.serialize().hex()))

	# Execure Proof-of-Work for block header
	# For sake of simplicity this example uses sha256d as PoW function
	raw_header, signature = miner({
		'version': 1,
		'prev_block': "0000000000000000000000000000000000000000000000000000000000000000",
		'merkle_root': "4e9a7450cf706f05c9f7cf6b6f4c4c267e911c0d8d5066df1da4deb318637fd3",
		'timestamp': 1568015489,
		'bits': 524287999,
		'nonce': 0,
		'miner_pubkey': pubkey.serialize().hex()
	}, privkey)

	mined_hash = sha256d(raw_header + signature)
	mined_header = header_deserialize(raw_header)

	print('Block hash:', mined_hash[::-1].hex())
	print('Block nonce:', mined_header['nonce'])

	# Validate Proof-of-Work
	pow_validation = validate_target(mined_hash, mined_header['bits'])
	print('PoW validation: {}'.format(pow_validation))

	# Validate header signature
	sighash = ripemd160(raw_header)
	miner_pubkey = bytes(bytearray.fromhex(mined_header['miner_pubkey']))
	header_signature = signature[::-1]
	signature_validation = validate_signature(sighash, header_signature, miner_pubkey)
	print('Signature validation: {}'.format(signature_validation))


if __name__ == '__main__':
	main()
