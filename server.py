#Isatou Sanneh
#Secure chat project
#isanneh@ccny.cuny.edu

from Crypto.Cipher import AES
import socket
import select
import pickle
from Crypto import Random
from Crypto.Random import random as R
import string
import sys
import hashlib as H
import time


#dictionaries to hold clients' info
usernames={}	
status={}
login_attempts={}
session_keys={}
ack={}
messages={}
state={}
message_size={}
received_messages={}
socket_connection_index={}
queue = {}
CONNECTION_LIST = []
USER_NAME_LIST=[]
SESSION_KEYS=[]
PRIVATE_KEYS=[]

block_size=16
buffer_size=1024
safe_buffer_size=buffer_size - (2 * block_size)	#to make sure chunk of encrypted data sent is not more than buffer_size


#this function adds padding to plaintext to ensure plaintext is in multiples of 16 bits before encryption
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


#this function removes padding of the plaintext after decryption
def removePadding(text, session_key):	
	data_length=len(text)
	if(text.find(session_key) == -1):
		return text
	else:
		padding_start_index=text.find(session_key)
		return text[:padding_start_index]

#this function encrypts plaintext
def encryption(plaintext, padding, iv, key):
	mode = AES.MODE_CBC
	encryptor = AES.new(key, mode,iv)
	data= addPadding(plaintext, padding)
	ciphertext = encryptor.encrypt(data)
	return ciphertext

#this function decrypts ciphertext
def decryption(ciphertext, padding, iv, key):
	mode = AES.MODE_CBC
	decryptor = AES.new(key, mode, iv)
	data = decryptor.decrypt(ciphertext)
	plaintext=removePadding(data, padding)
	return plaintext


#this function sends incoming messages to logged in clients
def send_msg_content (client_socket):
	rnd=session_keys[str(client_socket)]
	key=state[str(usernames[str(client_socket)])]
	msg_params=messages[str(client_socket)]	
	current_start_index=msg_params[1]
	current_end_index=msg_params[2]
	current_chunk=msg_params[1]
	current_end_index=current_end_index + safe_buffer_size
	if(current_end_index > len(msg_params[0])):
		current_end_index=len(msg_params[0]) + 1
	if(msg_params[2] >= len(msg_params[0])):
		ack[str(client_socket)] = 2
	else:
		messages[str(client_socket)]=[msg_params[0], msg_params[2], current_end_index]
	msg=msg_params[0]
	segment=msg[msg_params[1]:msg_params[2]]
	sock.send (encryption(segment, rnd[0], rnd[1], key))


#this function sends size of incoming message to clients except for client that sent the message
#it is also used to send the size of announcements to clients
def send_msg_header (client_socket, msg, user):
        for sock in CONNECTION_LIST:
		if sock != server_socket :
			if ((status[str(sock)] == 'receiving' or status[str(sock)] == 'sending' or status[str(sock)] == 'busy') and sock != client_socket):
				outstanding=queue[str(sock)] 
				outstanding.append([client_socket, msg, user])
				queue[str(sock)] = outstanding
			if status[str(sock)] == 'connected' and sock != client_socket  :
				rnd=session_keys[str(sock)]
				key=state[str(usernames[str(sock)])]
				sender=usernames[str(client_socket)]
				status[str(sock)]= 'receiving'
				ack[str(sock)]= 1
				size=len(encryption(msg, rnd[0], rnd[1], key))
				if(size < buffer_size):
					current_end_index=len(msg)
				else:
					current_end_index = buffer_size
				messages[str(sock)]=[msg, 0, current_end_index, len(msg)]
				msg2=[]
				if(user == 'client'):
					msg2.append((encryption(sender, rnd[0], rnd[1], key)))
				else:
					msg2.append((encryption('System', rnd[0], rnd[1], key)))
				msg2.append((encryption(str(len(msg)), rnd[0], rnd[1], key)))
				msg2.append((encryption('0', rnd[0], rnd[1], key)))
				sock.send (pickle.dumps(msg2))


#this function sends size of the next incoming message in the queue to clients except for client that sent the message
#it is also used to send the size of announcements to clients
def queue_send_msg_header (client_socket, msg, user, socket_current):
	if sock != server_socket :
		rnd=session_keys[str(socket_current)]
		key=state[str(usernames[str(socket_current)])]
		sender=usernames[str(client_socket)]
		remaining=queue[str(sock)]
		del remaining[0]
		queue[str(sock)]=remaining

		status[str(socket_current)]= 'receiving'
		ack[str(socket_current)]= 1
		size=len(encryption(msg, rnd[0], rnd[1], key))
		if(size < buffer_size):
			current_end_index=len(msg)
		else:
			current_end_index = buffer_size
		messages[str(sock)]=[msg, 0, current_end_index, len(msg)]
		msg2=[]
		if(user == 'client'):
			msg2.append((encryption(sender, rnd[0], rnd[1], key)))
		else:
			msg2.append((encryption('System', rnd[0], rnd[1], key)))
		msg2.append((encryption(str(len(msg)), rnd[0], rnd[1], key)))
		msg2.append((encryption('0', rnd[0], rnd[1], key)))
		socket_current.send (pickle.dumps(msg2))
				

port=12345
server_socket = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind (('127.0.0.1', port))
server_socket.setsockopt (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.listen (5) 
print "Isatou Sanneh's Chat server at ", server_socket.getsockname(), " is active" 

CONNECTION_LIST.append (server_socket)
usernames[str(server_socket)]='System'
random_number = R.StrongRandom()

while True:	
        read_sockets, write_sockets, error_sockets = select.select (CONNECTION_LIST, [], [])

        for sock in read_sockets:
                if sock == server_socket:
                        client_socket, addr = sock.accept()
                        print 'A new client from (%s, %s) has connected' %addr
			socket_connection_index[str(client_socket)]=len(CONNECTION_LIST)
			connection_index_keys=socket_connection_index.keys()
                        CONNECTION_LIST.append (client_socket)
			status[str(client_socket)]='user'
			ack[str(client_socket)]=0
			queue[str(client_socket)] = []
			
			#random values used as session keys: #server sends client 3 session keys: 1st one is used as padding for plaintext since plaintext blocks for encryption should be in multiples of 16, 2nd one is used as salt for randomness of encryption, 3rd is used as temporary secret key for encryption and decryption until client is authenticated
			rnd1=''.join(R.choice(string.ascii_uppercase + string.digits) for i in range(random_number.randint(block_size,block_size)))
			
			rnd2=''.join(R.choice(string.ascii_uppercase + string.digits) for i in range(random_number.randint(block_size,block_size)))

			rnd3=''.join(R.choice(string.ascii_uppercase + string.digits) for i in range(random_number.randint(block_size,block_size)))

			SESSION_KEYS.append([client_socket, rnd1])
			session_keys[str(client_socket)]= [rnd1, rnd2, rnd3]
			session_key=[]
			session_key.append([rnd1, rnd2, rnd3])
			data="Welcome to Isatou's Chat System. Enter username:"
			msg2=[]
			msg2.append((encryption('System', rnd1, rnd2, rnd3)))
			msg2.append((encryption(data, rnd1, rnd2, rnd3)))
			msg2.append((encryption('1', rnd1, rnd2, rnd3)))

			#username and password file is opened
			unpickle_users = open('password.txt', 'r')
			users = pickle.load(unpickle_users)
			unpickle_users.close()
			received_messages[str(client_socket)]=''
			message_size[str(client_socket)]=0
			client_socket.send(pickle.dumps(session_key))	#session keys are sent to client

                else:
                        data = sock.recv (buffer_size)	#message from client

			if(status[str(sock)] == 'disconnected'):	#client is logging out
				del CONNECTION_LIST[(socket_connection_index[str(sock)])]
				for i in range(0,len(CONNECTION_LIST)):
					if((socket_connection_index[str(sock)] == 0) ):
						socket_connection_index[connection_index_keys[i]]=socket_connection_index[connection_index_keys[i]] - 1
					elif(socket_connection_index[connection_index_keys[i]] > socket_connection_index[str(sock)]):

						socket_connection_index[connection_index_keys[i]]=socket_connection_index[connection_index_keys[i]] - 1
				sock.close()
				announcement=usernames[str(sock)] + ' has left the chat!' 
				send_msg_header(sock,announcement, 'system')


			elif(status[str(sock)] == 'sending'): #client is sending a message to other clients
				rnd=session_keys[str(sock)]
				key=state[str(usernames[str(sock)])]
				decrypted_data=decryption(data, rnd[0], rnd[1], key)
				txt=received_messages[str(sock)]
				txt= txt + decrypted_data
				received_messages[str(sock)]= txt
				
				if(len(received_messages[str(sock)]) == message_size[str(sock)]):
					status[str(sock)]= 'connected'
					received_messages[str(sock)]=''
					sock.send(pickle.dumps(1))
					if(len(queue[str(sock)])  != 0):
						next=queue[str(sock)]
						queue_send_msg_header(next[0][0], next[0][1], next[0][2], sock)
					send_msg_header(sock, txt, 'client')
				else:
					sock.send(pickle.dumps(1))

			elif(status[str(sock)] == 'receiving' and ack[str(sock)] == 1): #client is receiving a message 
				send_msg_content(sock)

			elif(status[str(sock)] == 'receiving' and ack[str(sock)] == 2): #client has finished receiving a message
				status[str(sock)] = 'connected'
				ack[str(sock)] == 1
				if(len(queue[str(sock)])  != 0):
					next=queue[str(sock)]
					queue_send_msg_header(next[0][0], next[0][1], next[0][2], sock)

			elif(status[str(sock)] == 'user' and ack[str(sock)]==0): #server requests for username
				rnd=session_keys[str(sock)]
				data='Enter username'
				msg2=[]
				msg2.append((encryption('System', rnd[0], rnd[1], rnd[2])))
				msg2.append((encryption(data, rnd[0], rnd[1], rnd[2])))
				msg2.append((encryption('1', rnd[0], rnd[1], rnd[2])))
				status[str(sock)] == 'user'
				sock.send(pickle.dumps(msg2))
				ack[str(sock)]=1

			elif(status[str(sock)] == 'user' and ack[str(sock)]==1):	#server sends secret key (random session key) for encryption and decryption of message
				rnd=session_keys[str(sock)]
				decrypted_data=decryption(data, rnd[0], rnd[1], rnd[2])
				data=decrypted_data
				if(data == rnd[2]):
					sock.send('1')
					del CONNECTION_LIST[(socket_connection_index[str(sock)])]
					for i in range(0,len(CONNECTION_LIST)):
						if((socket_connection_index[str(sock)] == 0) ):
							socket_connection_index[connection_index_keys[i]]=socket_connection_index[connection_index_keys[i]] - 1
						elif(socket_connection_index[connection_index_keys[i]] > socket_connection_index[str(sock)]):
							socket_connection_index[connection_index_keys[i]]=socket_connection_index[connection_index_keys[i]] - 1
					sock.close()
				else:
		

					status[str(sock)] == 'user'                     
					usernames[str(sock)]=data
					ack[str(sock)]=2
					sock.send(encryption(str(rnd[2]), rnd[0], rnd[1], rnd[2]))
  
			elif(status[str(sock)] == 'user' and ack[str(sock)]==2):	#server requests password
				rnd=session_keys[str(sock)]
				status[str(sock)] = 'password'
				data='Enter Password'
				msg2=[]
				msg2.append((encryption('System', rnd[0], rnd[1], rnd[2])))
				msg2.append((encryption(data, rnd[0], rnd[1], rnd[2])))
				msg2.append((encryption('1', rnd[0], rnd[1], rnd[2])))
				ack[str(sock)]=1
				sock.send(pickle.dumps(msg2))

			elif(status[str(sock)] == 'password_correct'):	#client authentication is succesful
				rnd=session_keys[str(sock)]
				status[str(sock)] = 'connected'

				ack[str(sock)]= 1
				data='You are logged in!'
				msg2=[]
				msg2.append((encryption('System', rnd[0], rnd[1], rnd[2])))
				msg2.append((encryption(data, rnd[0], rnd[1], rnd[2])))
				msg2.append((encryption('0', rnd[0], rnd[1], rnd[2])))
				sock.send(pickle.dumps(msg2))
				announcement=usernames[str(sock)] + ' has joined the chat!'
				send_msg_header(sock, announcement, 'system')
				
			elif(status[str(sock)] == 'password_incorrect'):	#authentication is unsuccessful
				rnd=session_keys[str(sock)]
				status[str(sock)] = 'user'
				data='Login failed! Enter Username:'
				msg2=[]
				msg2.append((encryption('System', rnd[0], rnd[1], rnd[2])))
				msg2.append((encryption(data, rnd[0], rnd[1], rnd[2])))
				msg2.append((encryption('1', rnd[0], rnd[1], rnd[2])))
				sock.send(pickle.dumps(msg2))

			elif(status[str(sock)] == 'password_incorrect_all'):	#client is disconnected after 3 unsuccessful authentication attempts 
				rnd=session_keys[str(sock)]
				status[str(sock)] = 'kickout'
				data='You have exceeded number of logins allowed! You have been disconnected!'
				msg2=[]
				msg2.append((encryption('System', rnd[0], rnd[1], rnd[2])))
				msg2.append((encryption(data, rnd[0], rnd[1], rnd[2])))
				msg2.append((encryption('3', rnd[0], rnd[1], rnd[2])))
				del CONNECTION_LIST[(socket_connection_index[str(sock)])]
				for i in range(0,len(CONNECTION_LIST)):
					if((socket_connection_index[str(sock)] == 0) ):
						socket_connection_index[connection_index_keys[i]]=socket_connection_index[connection_index_keys[i]] - 1
					elif(socket_connection_index[connection_index_keys[i]] > socket_connection_index[str(sock)]):

						socket_connection_index[connection_index_keys[i]]=socket_connection_index[connection_index_keys[i]] - 1
				sock.send(pickle.dumps(msg2))
				sock.close()
 
			elif(status[str(sock)] == 'password'): #password received
				ack[str(sock)]=1
				rnd=session_keys[str(sock)]
				decrypted_data=decryption(data, rnd[0], rnd[1], rnd[2])
				data=decrypted_data

				if(data == rnd[2]):
					sock.send('1')
					del CONNECTION_LIST[(socket_connection_index[str(sock)])]
					for i in range(0,len(CONNECTION_LIST)):
						if((socket_connection_index[str(sock)] == 0) ):
							socket_connection_index[connection_index_keys[i]]=socket_connection_index[connection_index_keys[i]] - 1
						elif(socket_connection_index[connection_index_keys[i]] > socket_connection_index[str(sock)]):
							socket_connection_index[connection_index_keys[i]]=socket_connection_index[connection_index_keys[i]] - 1
					sock.close()

				else:

					password=data
					#hash password 100 times 
					for i in range(0,100):
						password_hash=H.sha512(password).hexdigest()
						password=password_hash

					#checking if username and password pair is correct.  session key is sent as secret key if authentication is unsuccessful, and client's private key is sent after successful authentication

					if((usernames[str(sock)] in users) == 0):	#username is not in the members list
						if((str(sock) in login_attempts) == 0):
							login_attempts[str(sock)]=1
							status[str(sock)]= 'password_incorrect'
							sock.send(encryption(str(rnd[2]), rnd[0], rnd[1], rnd[2]))

						elif(login_attempts[str(sock)] == 2):
							status[str(sock)] = 'password_incorrect_all'
							sock.send(encryption(str(rnd[2]), rnd[0], rnd[1], rnd[2]))
						else:
							login_attempts[str(sock)]= login_attempts[str(sock)] + 1
							status[str(sock)] = 'password_incorrect'
							sock.send(encryption(str(rnd[2]), rnd[0], rnd[1], rnd[2]))

					elif(users[str(usernames[str(sock)])] == password):	
						status[str(sock)] = 'password_correct'

						#private key for encryption and decryption of data for the AES CBC used is 128 bits.  the hash of the user's password is 512 bits.  so the hash is divided into 4 parts, and one of the four parts is randomly chosen as the private key for every session

						rnd_num=R.choice(str(1) + str(2) + str(3) + str(4) ) 
						start_index= 32 * (int(rnd_num) - 1) 
						end_index= 32 * int(rnd_num)  
						hash_password=users[str(usernames[str(sock)])]
						private_key=hash_password[start_index:end_index]
						state[str(usernames[str(sock)])]=private_key
						sock.send(encryption(private_key, rnd[0], rnd[1], rnd[2]))

					else:
						if((str(sock) in login_attempts) == 0):
							login_attempts[str(sock)]=1
							status[str(sock)]= 'password_incorrect'
							sock.send(encryption(str(rnd[2]), rnd[0], rnd[1], rnd[2]))
						
						elif(login_attempts[str(sock)] == 2):
							status[str(sock)] = 'password_incorrect_all'
							sock.send(encryption(str(rnd[2]), rnd[0], rnd[1], rnd[2]))
						else:
							login_attempts[str(sock)]= login_attempts[str(sock)] + 1
							status[str(sock)] = 'password_incorrect'
							sock.send(encryption(str(rnd[2]), rnd[0], rnd[1], rnd[2]))

			elif(status[str(sock)] == 'busy'):
				key=state[str(usernames[str(sock)])]
				rnd=session_keys[str(sock)]
				decrypted_data=decryption(data, rnd[0], rnd[1], key) #size of file to be sent
				if(decrypted_data == 'quit'): #client wants to logout
					status[str(sock)]='disconnected'
					sock.send('1')
				else:

					data=decrypted_data	
					status[str(sock)]='sending'
					message_size[str(sock)]=int(decrypted_data)
					sock.send (pickle.dumps(1))
			else:	
				key=state[str(usernames[str(sock)])]
				rnd=session_keys[str(sock)]
				decrypted_data=decryption(data, rnd[0], rnd[1], key) #size of file to be sent
				data=decrypted_data
				if(decrypted_data == 'busy'): 
					status[str(sock)]='busy' 



server_socket.close()



