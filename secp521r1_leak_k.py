import ecdsa
import random
import libnum
import hashlib
import sys


G = ecdsa.NIST521p.generator
order = G.order()
print ("Curve detail")
print (G.curve())
print ("Order:",order)
print ("Gx:",G.x())
print ("Gy:",G.y())


priv = random.randrange(1,order)
 
Public_key = ecdsa.ecdsa.Public_key(G, G * priv)
Private_key = ecdsa.ecdsa.Private_key(Public_key, priv)
 
k1 = random.randrange(1, 2**127)

msg1="Hello"
if (len(sys.argv)>1):
	msg1=(sys.argv[1])

m1 = int(hashlib.sha256(msg1.encode()).hexdigest(),base=16)
 
sig1 = Private_key.sign(m1, k1)


print ("\nMessage 1: ",msg1)

print ("Sig 1 r,s: ",sig1.r,sig1.s)

r1_inv = libnum.invmod(sig1.r, order)
s1 = sig1.s
 

try_private_key = (r1_inv * ((k1 * s1) - m1)) % order

print ()
print ("Found Key: ",try_private_key)
print ()
print ("Key: ",priv)

if (ecdsa.ecdsa.Public_key(G, G * try_private_key) == Public_key):
	print("\nThe private key has been found")
	print (try_private_key)
