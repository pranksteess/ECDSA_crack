import ecdsa
import random
import libnum
import hashlib
import sys


G = ecdsa.SECP256k1.generator
order = G.order()

priv1 = random.randrange(1,order)
 
Public_key = ecdsa.ecdsa.Public_key(G, G * priv1)
x1 = ecdsa.ecdsa.Private_key(Public_key, priv1)

k = random.randrange(1, 2**127)

msg1="Hello"
msg2="Hello1"

if (len(sys.argv)>1):
	msg1=(sys.argv[1])
if (len(sys.argv)>2):
	msg2=(sys.argv[2]) 



h1 = int(hashlib.sha256(msg1.encode()).hexdigest(),base=16)
h2 = int(hashlib.sha256(msg2.encode()).hexdigest(),base=16)
 
sig1 = x1.sign(h1, k)
sig2 = x1.sign(h2, k)

r1,s1 = sig1.r,sig1.s
r2,s2 = sig2.r,sig2.s

valinv = libnum.invmod( r1*(s1-s2),order)

x1rec = ((s2*h1-s1*h2) * (valinv)) % order

print ("Message 1: ",msg1)
print (f"Signature r={r1}, s={s1}")
print ("\nMessage 2: ",msg2)
print (f"Signature r={r2}, s={s2}")


print ("\nPrivate key",priv1)
print ("\nPrivate recovered ",x1rec)

valinv = libnum.invmod( (s1-s2),order)

k1rec = ((h1-h2) * valinv) % order

print ("\nK: ",k)
print ("\nK recovered ",k1rec)
