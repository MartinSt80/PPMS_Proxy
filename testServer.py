#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import pickle
import struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from threading import *
import Options



# starts a proxy listening for PUMAPI calls
class ListeningSocket(Thread):

	def __init__(self, ip, port):
		Thread.__init__(self)
		self.ip = ip
		self.port = int(port)
		if port == proxy_options.getValue('API_port'):
			self.type = 'API'

		AES_plainkey = proxy_options.getValue('AES_key')
		AES_key = SHA256.new()
		AES_key.update(AES_plainkey)
		self.AES_key = AES_key.digest()
		self.start()


	def run(self):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.bind((self.ip, self.port))
		self.sock.listen(5)
		while True:
			self.client_connection, self.client_address = self.sock.accept()
			CallBack(self.client_connection, self.client_address, self.AES_key)

class CallBack(Thread):

	def __init__(self, connection, address, AES_key):
		Thread.__init__(self)
		self.connection = connection
		self.address = address
		self.AES_key = AES_key
		self.start()

	# get pickled API parameter dict from clientproxy
	def run(self):

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

		encrypted_call = receive_data(self.connection)

		iv2 = encrypted_call[:AES.block_size]
		ciphered_msg = encrypted_call[AES.block_size:]

		decryptor = AES.new(self.AES_key, AES.MODE_CFB, iv2)
		decrypted_message = decryptor.decrypt(ciphered_msg)
		data_from_client = pickle.loads(decrypted_message)


		print self.address[0] + ' says ' + data_from_client['h'] + data_from_client['s']
		server_response = {'h': 'Hello ', 'c': 'client'}

		iv = Random.new().read(AES.block_size)
		cipher = AES.new(self.AES_key, AES.MODE_CFB, iv)
		pickled_response = pickle.dumps(server_response)
		server_message = iv + cipher.encrypt(pickled_response)

		data_to_client = struct.pack('>I', len(server_message)) + server_message
		self.connection.sendall(data_to_client)
		self.connection.close()


proxy_options = Options.OptionReader('ServerOptions.txt')
PUMAPIproxy = ListeningSocket(proxy_options.getValue('host_ip'), proxy_options.getValue('API_port'))




