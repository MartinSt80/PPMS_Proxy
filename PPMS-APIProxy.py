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

from lib import Options, Errors



# starts a proxy listening for PUMAPI calls
class ListeningSocket(Thread):

	def __init__(self, ip, port):
		Thread.__init__(self)
		self.ip = ip
		self.port = int(port)

		if port == PROXY_OPTIONS.getValue('API_port'):
			self.type = 'API'			
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
				# retrieve AES-key for the ip-address, close connection if ip-address is not in file
				try:
					AES_key = self.AES_keys.getValue(client_address[0])
					CallAPI(client_connection, AES_key)
				except KeyError:
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
			# create a new API call object, add the transmitted parameters and send the API response back to sender
			header = {'Content-Type': 'application/x-www-form-urlencoded'}
			API_type = parameters.pop('API_type')

			if API_type == 'PUMAPI':
				parameters['apikey'] = PROXY_OPTIONS.getValue('PUMAPI_key')
				URL = PROXY_OPTIONS.getValue('PUMAPI_URL')
			elif API_type == 'API2':
				parameters['apikey'] = PROXY_OPTIONS.getValue('API2_key')
				URL = PROXY_OPTIONS.getValue('API2_URL')
			else:
				raise Errors.APIError('Unknown API interface type, must be PUMAPI or API2')

			response = requests.post(URL, headers=header, data=parameters)

			# check if we got a proper response, HTTP status code == 200
			try:
				if not response.status_code == 200:
					raise Errors.APIError('API didn\'t return a proper response')

				# check if there is some data in the response, empty response, check parameters, options
				if not response.text:
					raise Errors.APIError('Empty response from API')
			except Errors.APIError as e:
				response = e

			response_from_Paris = pickle.dumps(response)

			iv = Random.new().read(AES.block_size)
			encryptor = AES.new(self.AES_key, AES.MODE_CFB, iv)
			encrypted_data = iv + encryptor.encrypt(response_from_Paris)
			data_from_Paris = struct.pack('>I', len(encrypted_data)) + encrypted_data
			self.connection.sendall(data_from_Paris)


class CallTracker(Thread):

	def __init__(self, connection):
		Thread.__init__(self)
		self.connection = connection
		self.start()

	# get encrypted and pickled API parameter dict from client
	def run(self):

		pickled_call = self.connection.recv(4096)
		parameters = pickle.loads(pickled_call)

		# create a new tracker call object, add the transmitted parameters and send the API response back to sender
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
APIproxy = ListeningSocket(PROXY_OPTIONS.getValue('host_ip'), PROXY_OPTIONS.getValue('API_port'))
trackerproxy = ListeningSocket(PROXY_OPTIONS.getValue('host_ip'), PROXY_OPTIONS.getValue('tracker_port'))



