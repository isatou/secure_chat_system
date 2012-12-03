

'''
session key = random variable 
hash of password: private key used by client for decryption
'''

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




'''users={'bob': 'pass1', 'alice': 'pass2', 'cindy': 'pass3', 'john': 'pass4'}

users={'bob': 'c2457d3096fc9c2b6f6bf0ffc936f47812073a34412f9b6f8162afacfe6ea5ff5aab46fcc12060c6ac1cae57f83b4905fbe14a4a32bad62c820720a51159345f', 'alice': '5d8562f8212ed3712585f93603c2ad09ed258ce8d4d63c351e99ee51359e4f17522635f5e28b1410abc26fdef2e91ce3c6307a9962b515154997b7a82c0ce3cb', 'cindy': '7b35381b6bde7e3c3536d59566a217ea4af76786ad94220231b20a522532b8b4384a4b5a9c4e3291cd2d6af11f030fa365e6f7e1feedc4c3fa17a7785c4f5b83', 'john': 'f91b850a442e203da03049c509cb1d5c7b18dcab7f581318efc838f6720b85d617608f31ce2f7d12e6d03e2f804ca329f3f7376a122f09542ef4af5482dcc8af'}



password="pass4"
#hash password 100 times 
#hash of password is used as secret key for client
commitment=H.sha256(password).hexdigest()
print H.sha512(password).digest_size
#print commitment
for i in range(0,100):
	commitment=H.sha1(password).hexdigest()
	password=commitment

print "commitment"
print commitment

if(('alice' in users) == 1):
	print "yes"
print users



from Crypto import Random
from Crypto.Random import random as R
import string


#randomly make a guess
random_number = R.StrongRandom()'''











