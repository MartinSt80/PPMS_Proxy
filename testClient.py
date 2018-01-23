#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import pickle
import struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

from lib import Options


def	sendToProxy(message):

	def receive_data(sock):	# Read message length and unpack it into an integer
		raw_msglen = recvall(sock, 4)
		if not raw_msglen:
			return None
		msglen = struct.unpack('>I', raw_msglen)[0]
		# Read the message data
		return recvall(sock, msglen)

	def recvall(sock, n): # Helper function to recv n bytes or return None if EOF is hit
		data = ''
		while len(data) < n:
			packet = sock.recv(n - len(data))
			if not packet:
				return None
			data += packet
		return data

	proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	proxy_socket.connect((APIoptions.getValue('proxy_address'), int(APIoptions.getValue('API_port'))))
	proxy_socket.sendall(message)

	response = receive_data(proxy_socket)
	proxy_socket.close()
	return response

APIoptions = Options.OptionReader('ClientOptions.txt')

test_dict = {'h': 'Hello ', 's': 'Server'}
pickled_dict = pickle.dumps(test_dict)

AES_plainkey = APIoptions.getValue('AES_key')
AES_key = SHA256.new()
AES_key.update(AES_plainkey)
AES_key = AES_key.digest()

iv = Random.new().read(AES.block_size)
cipher = AES.new(AES_key, AES.MODE_CFB, iv)
msg = iv + cipher.encrypt(pickled_dict)
data_to_server = struct.pack('>I', len(msg)) + msg

response = sendToProxy(data_to_server)

iv2 = response[:AES.block_size]
ciphered_msg = response[AES.block_size:]

decryptor = AES.new(AES_key, AES.MODE_CFB, iv2)
decrypted_message = decryptor.decrypt(ciphered_msg)
response_dict = pickle.loads(decrypted_message)

print response_dict['h'] + response_dict['c']