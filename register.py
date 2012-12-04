import sys
from subprocess import *
import cPickle as pcl
from Crypto import Random
from Crypto.Random import random as R
import hashlib as H
import string
import pickle


# open file
unpickle_users = open('password.txt', 'r')

users = pickle.load(unpickle_users)

unpickle_users.close()

username=raw_input('Choose a username: ')

while((username in users) == 1):
	username=raw_input('Username is taken.  Choose another username: ')


password=raw_input('Choose a password: ')


#hash password 100 times 
#hash of password is used as secret key for client
for i in range(0,100):
	password_hash=H.sha512(password).hexdigest()
	password=password_hash

users[str(username)]=password

file = open('password.txt', 'w')


pickle.dump(users,file)

# close the file, and your pickling is complete
file.close()



print "Thank you.  You account has been created!"

#connection

# open file
unpickle_state = open('state.txt', 'r')

state = pickle.load(unpickle_state)

unpickle_state.close()

state[str(username)]=[0,0]

#store state

file = open('state.txt', 'w')


pickle.dump(state,file)

# close the file, and your pickling is complete
file.close()








