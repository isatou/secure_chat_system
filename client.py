#Isatou Sanneh
#Secure chat project
#isanneh@ccny.cuny.edu

from Crypto.Cipher import AES
import socket
import sys
from Crypto import Random
from Crypto.Random import random as R
import string
import pickle
import time
import sys
import getpass 


port=12345
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("localhost", port))

block_size=16
buffer_size=1024
safe_buffer_size=buffer_size - (2 * block_size)	#to make sure chunk of encrypted data sent is not more than buffer_size

def addPadding(text, session_key):
	data_length=len(text)
	if((data_length % block_size) == 0):
		return text
	else:
		new_text1= text + session_key
		new_data1_length=len(new_text1)
		if((new_data1_length % block_size) == 0):
			return new_data1_length
		else:
			remaining_length2=(new_data1_length % block_size)
			new_text2=new_text1 + session_key[:(block_size - remaining_length2)]
			return new_text2

def removePadding(text, session_key):	
	data_length=len(text)
	if(text.find(session_key) == -1):
		return text
	else:
		padding_start_index=text.find(session_key)
		return text[:padding_start_index]

def encryption(plaintext, padding, iv, key):
	mode = AES.MODE_CBC
	encryptor = AES.new(key, mode,iv)
	data= addPadding(plaintext, padding)
	ciphertext = encryptor.encrypt(data)
	return ciphertext

def decryption(ciphertext, padding, iv, key):
	mode = AES.MODE_CBC
	decryptor = AES.new(key, mode, iv)
	data = decryptor.decrypt(ciphertext)
	plaintext=removePadding(data, padding)
	return plaintext


session_keys= client_socket.recv(buffer_size)	#client receives 3 session keys: 1st one is used as padding for plaintext since plaintext blocks for encryption should be in multiples of 16 bits, 2nd one is used as salt for randomness of encryption, 3rd is used as temporary secret key for encryption and decryption until client is authenticated

session_keys=pickle.loads(session_keys)
client_socket.send ('1')

data_rcvd= client_socket.recv(buffer_size)	#username request	
data_rcvd=pickle.loads(data_rcvd)


sender=decryption(data_rcvd[0], session_keys[0][0], session_keys[0][1],session_keys[0][2])
decrypted_data=decryption(data_rcvd[1], session_keys[0][0], session_keys[0][1], session_keys[0][2])
flag=decryption(data_rcvd[2], session_keys[0][0], session_keys[0][1], session_keys[0][2])
print sender, " says:" , decrypted_data

request='username'


ack=0

import threading
from time import sleep

#disconnect client if he or she does send authentication details for a time period of 2 minutes.  this timer is started once a user presses ctrl key to type but doesn't send anything

response = 0
class TimeThread(threading.Thread):
	def __init__(self, max_):
		threading.Thread.__init__(self)
		self.max_ = max_
	def run(self):
		sleep(120)	#
		if (response == 0): # the time is up: if the user didn't enter anything, print stuff.
			client_socket.send ((encryption(str(session_keys[0][2]), session_keys[0][0], session_keys[0][1], session_keys[0][2])))
			data = client_socket.recv(buffer_size)
			client_socket.close()
			print "You have been disconnected because you took too long to respond!"
			sys.exit()



#this loop is valid until client is authenticated: client's secret key will be recieved and it will now  be used for encryption and decryption of messages
while(int(flag) == 1):
	client_socket.settimeout(120)
	#print "Press ctrl once to type:"

	try:

		if(ack == 0):	#client receives private key from server

			try:

				data = client_socket.recv(buffer_size)
				key=decryption(data, session_keys[0][0], session_keys[0][1], session_keys[0][2])

				ack=1
				client_socket.send ('1')

			
			except 	socket.timeout:	#client doesn't even start typing requested authentication details for a time period of two minutes. a flag is set to disconnect client
				client_socket.settimeout(None)
				flag=4
				break

		elif(ack == 1):	#client receives message from server
			data = client_socket.recv(buffer_size)
			data2=pickle.loads(data)
			sender=decryption(data2[0], session_keys[0][0], session_keys[0][1], session_keys[0][2])
			decrypted_data=decryption(data2[1], session_keys[0][0], session_keys[0][1], session_keys[0][2])
			flag=decryption(data2[2], session_keys[0][0], session_keys[0][1], session_keys[0][2])
			plain=decrypted_data

			print "#############################################"
			print sender, " says:" , plain
			print "#############################################"
			ack=0

	except KeyboardInterrupt:	#client can send message to server

			if(request == 'username'):
			#data is sent if client is not idle for 2 mins, otherwise, client is disconnected
				time_thread = TimeThread(3)
				time_thread.start()	
				data = raw_input ( "Press Enter to send:" )
				response = 1 
				request = 'password'
			elif(request == 'password'): 
				time_thread = TimeThread(3)
				time_thread.start()
				data=getpass.getpass("Press Enter to send:")	
				response = 1 
				request = 'username'
	
			client_socket.send ((encryption(data, session_keys[0][0], session_keys[0][1], session_keys[0][2])))


if(int(flag) == 3):	#client is disconnected from chat after 3 attempts to login with invalid usernames and/or passwords
	client_socket.send ('1')
	client_socket.close()
	print "You have been disconnected!"
	sys.exit()

ack2=0


#disconnect client if he or she does send authentication details for a time period of 2 minutes.  
if(int(flag) == 4):
	client_socket.send ((encryption(str(session_keys[0][2]), session_keys[0][0], session_keys[0][1], session_keys[0][2])))
	data = client_socket.recv(buffer_size)
	client_socket.close()
	print "You have been disconnected because you took too long to respond!"
	sys.exit()

client_socket.settimeout(None)

while 1:
	print "Press ctrl once to type a message, and twice to logout"	#no incoming messages received, so client can send a message

	try:

		th=[]
		if(ack2 == 0):
			data1 = client_socket.recv(buffer_size)	#size of incoming message
			data1=pickle.loads(data1)
			decrypted_data=decryption(data1[1], session_keys[0][0], session_keys[0][1], key)
			sender=decryption(data1[0], session_keys[0][0], session_keys[0][1], key)
			total_data_size= int(decrypted_data)
			ack2=1
			size_of_data=0
			msg=''
			client_socket.send('1') #acknowledgement sent to server to send message

		elif(ack2 == 1):

			while(size_of_data != total_data_size ):	#message is received in chunks if it exceeds buffer size in order to prevent buffer overflows

				data3 = client_socket.recv(buffer_size)
				txt=decryption(data3, session_keys[0][0], session_keys[0][1], key)
				msg= msg + txt
				size_of_data= len(msg)
				#print "b", msg, size_of_data, total_data_size
				client_socket.send('1')
			print "#############################################"
			print sender, " says:" , msg
			print "#############################################"
			
			ack2=0


		elif(ack2 == 2):	#client sends messages in chunks if it exceeds buffer size
			data4 = client_socket.recv(buffer_size)	#acknowledgement from server for client to send data after client sends the total data size to be sent (size of sent after user types a message, see *size below* 

			message_size=len(message)
			if( message_size <= safe_buffer_size):
				client_socket.send ((encryption(message, session_keys[0][0], session_keys[0][1], key)))
				data4 = client_socket.recv(buffer_size)
			else:
				current_start_index=0
				current_end_index=safe_buffer_size
				msg_sent=0
				while(msg_sent != message_size):
					segment=message[current_start_index:current_end_index]
					msg_sent=msg_sent + len(segment)
					current_start_index=current_end_index
					current_end_index=current_end_index + safe_buffer_size
					if(current_end_index > message_size):
						current_end_index=message_size
					client_socket.send ((encryption(segment, session_keys[0][0], session_keys[0][1], key)))
					data4 = client_socket.recv(buffer_size)
			ack2=0
		elif(ack2 == 3):
			data4 = client_socket.recv(buffer_size)
			ack2=2

			client_socket.send ((encryption(str(len(data)), session_keys[0][0], session_keys[0][1],key)))	# *size* : size of message is sent

	except (KeyboardInterrupt): 

		try:
			client_socket.send ((encryption(str('busy'), session_keys[0][0], session_keys[0][1],key)))

			data = raw_input ( "Press Enter to send message:" )
			ack2=2
			message=data	#message to be sent

			client_socket.send ((encryption(str(len(data)), session_keys[0][0], session_keys[0][1],key)))	# *size* : size of message is sent
		except (KeyboardInterrupt):	#pressing the ctrl key twice logs off client
			msg2=[]
			msg2.append((encryption('user', session_keys[0][0], session_keys[0][1], key)))
			msg2.append((encryption(str('quit'), session_keys[0][0], session_keys[0][1],key)))
			msg2.append((encryption(str('quit'), session_keys[0][0], session_keys[0][1], key)))
			client_socket.send ((encryption('quit', session_keys[0][0], session_keys[0][1],key)))
			data4 = client_socket.recv(buffer_size)
			client_socket.send ((encryption('quit', session_keys[0][0], session_keys[0][1],key)))
			client_socket.close()
			print "You have been disconnected!"
			sys.exit()

		

	









