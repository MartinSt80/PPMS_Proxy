#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import pickle
import struct
import time
import requests

from threading import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

from lib import Options, PPMSAPICalls, Errors

from scapy.all import *


# starts a proxy listening for PUMAPI calls
class ListeningSocket(Thread):

	def __init__(self, ip, port):
		Thread.__init__(self)
		self.ip = ip
		self.port = int(port)

		if port == PROXY_OPTIONS.getValue('API_port'):
			self.type = 'API'
			# read client_ips, plainkeys from the key file, generate and store the AES-keys
			self.AES_keys = Options.OptionReader(PROXY_OPTIONS.getValue('AES_key_file'))
			for ip, plainkey in self.AES_keys.options.iteritems():
				AES_key = SHA256.new()
				AES_key.update(plainkey)
				AES_key = AES_key.digest()
				self.AES_keys.setValue(ip, AES_key)			
			
		if port == PROXY_OPTIONS.getValue('tracker_port'):
			self.type = 'tracker'
		
		self.start()

	def run(self):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.bind((self.ip, self.port))
		self.sock.listen(5)
		while True:
			client_connection, client_address = self.sock.accept()

			if self.type == 'API':
				# retrieve AES-key for the MAC-address, close connection if MAC-address is not in file
				# or no MAC-address resolved
				try:
					# arping: resolve MAC-address for client ip
					answered_list, unanswered_list = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=client_address[0]),
														timeout=2,
														retry=10,
														verbose=False)
					receiver = answered_list[0][1]
					receiver_mac = receiver[Ether].hwsrc

					AES_key = self.AES_keys.getValue(receiver_mac)
					CallAPI(client_connection, AES_key)
				except Exception:
					time.sleep(1)
					client_connection.close()

			if self.type == 'tracker':
				CallTracker(client_connection)


class CallAPI(Thread):

	def __init__(self, connection, AES_key):
		Thread.__init__(self)
		self.connection = connection
		self.type = type
		self.AES_key = AES_key
		self.start()

	# get encrypted and pickled API parameter dict from client
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

		# try to decrypt and unpickle; closes connection after 1 sec, if e.g. wrong key was used,
		try:
			iv2 = encrypted_call[:AES.block_size]
			ciphered_msg = encrypted_call[AES.block_size:]
			decryptor = AES.new(self.AES_key, AES.MODE_CFB, iv2)
			decrypted_message = decryptor.decrypt(ciphered_msg)
			parameters = pickle.loads(decrypted_message)
		except:
			time.sleep(1)
			self.connection.close()
		else:
			call_to_Paris = PPMSAPICalls.NewCall('PPMS API')

			try:
				response = call_to_Paris._performCall(parameters)
			except Errors.APIError as e:
				response = e

			response_from_Paris = pickle.dumps(response)

			iv = Random.new().read(AES.block_size)
			encryptor = AES.new(self.AES_key, AES.MODE_CFB, iv)
			encrypted_data = iv + encryptor.encrypt(response_from_Paris)
			data_from_Paris = struct.pack('>I', len(encrypted_data)) + encrypted_data

			# if client disconnects during sending data, close connection
			try:
				self.connection.sendall(data_from_Paris)
			except:
				self.connection.close()


class CallTracker(Thread):

	def __init__(self, connection):
		Thread.__init__(self)
		self.connection = connection
		self.start()


	# get pickled Tracker parameters dict from client
	def run(self):

		pickled_call = self.connection.recv(4096)
		parameters = pickle.loads(pickled_call)

		# create a new tracker call object, add the transmitted parameters
		newCall = NewTrackerCall()
		newCall.config(parameters)
		newCall.callParis()

		self.connection.close()

class NewTrackerCall:

	def __init__(self):
		self.header = {
		'Content-Type': 'application/x-www-form-urlencoded',
		}
		# explained in PUMAPI documentation
		self.data = {}
		self.URL = PROXY_OPTIONS.getValue('tracker_URL')

	# adds the parameters specific to each Tracker call
	def config(self, new_settings):
		self.data.update(new_settings)

	# generate full Tracker URL
	def callParis(self):
		url = self.URL + '?i=' + self.data['id'] + '&f=' + self.data['freq'] + '&u=' + self.data['user']
		requests.post(url, headers=self.header, data=self.data['code'])


PROXY_OPTIONS = Options.OptionReader('ProxyOptions.txt')
API_proxy = ListeningSocket(PROXY_OPTIONS.getValue('host_ip'), PROXY_OPTIONS.getValue('API_port'))
tracker_proxy = ListeningSocket(PROXY_OPTIONS.getValue('host_ip'), PROXY_OPTIONS.getValue('tracker_port'))



