# Bill Buchanan
# Code here: https://asecuritysite.com/encryption/ecd2
import ecdsa
import random
import libnum
import hashlib
import sys


G = ecdsa.NIST256p.generator
order = G.order()
priv = random.randrange(1,order)
 
Public_key = ecdsa.ecdsa.Public_key(G, G * priv)
Private_key = ecdsa.ecdsa.Private_key(Public_key, priv)
 
k = random.randrange(1, pow(2,127))

msg="Hello"
if (len(sys.argv)>1):
	msg=(sys.argv[1])

m = int(hashlib.sha256(msg.encode()).hexdigest(),base=16)
 
sig = Private_key.sign(m, k)


print ("Message 1: ",msg)

print ("Sig 1 r,s: ",sig.r,sig.s)

r_inv = libnum.invmod(sig.r, order)
s = sig.s
 
try_private_key = (r_inv * ((k * s) - m)) % order

print ("\nKey: ",priv)
print ("\nFound Key: ",try_private_key)

if (ecdsa.ecdsa.Public_key(G, G * try_private_key) == Public_key):
	print("\nThe private key has been found")
	print (try_private_key)
