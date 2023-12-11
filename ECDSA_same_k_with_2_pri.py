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

priv2 = random.randrange(1,order)
Public_key2 = ecdsa.ecdsa.Public_key(G, G * priv2)
x2 = ecdsa.ecdsa.Private_key(Public_key2, priv2)

k1 = random.randrange(1, 2**127)
k2 = random.randrange(1, 2**127)

msg1="Hello"
msg2="Hello1"
msg3="Hello3"
msg4="Hello4"

if (len(sys.argv)>1):
	msg1=(sys.argv[1])
if (len(sys.argv)>2):
	msg2=(sys.argv[2]) 
if (len(sys.argv)>3):
	msg3=(sys.argv[3]) 
if (len(sys.argv)>4):
	msg4=(sys.argv[4]) 



h1 = int(hashlib.sha256(msg1.encode()).hexdigest(),base=16)
h2 = int(hashlib.sha256(msg2.encode()).hexdigest(),base=16)
h3 = int(hashlib.sha256(msg3.encode()).hexdigest(),base=16)
h4 = int(hashlib.sha256(msg4.encode()).hexdigest(),base=16)
 
sig1 = x1.sign(h1, k1)
sig2 = x2.sign(h2, k1)
sig3 = x1.sign(h3, k2)
sig4 = x2.sign(h4, k2)

r1,s1 = sig1.r,sig1.s
r1_1,s2 = sig2.r,sig2.s
r2,s3 = sig3.r,sig3.s
r2_1,s4 = sig4.r,sig4.s

valinv = libnum.invmod( r1*r2*(s1*s4-s2*s3),order)

x1rec = ((h1*r2*s2*s3-h2*r2*s1*s3-h3*r1*s1*s4+h4*r1*s1*s3    ) * valinv)  % order

x2rec = ((h1*r2*s2*s4-h2*r2*s1*s4-h3*r1*s2*s4+h4*r1*s2*s3    ) * valinv)  % order


print ("Message 1: ",msg1)
print (f"Signature r={r1}, s={s1}")
print ("\nMessage 2: ",msg2)
print (f"Signature r={r1_1}, s={s2}")
print ("\nMessage 3: ",msg3)
print (f"Signature r={r2}, s={s3}")
print ("\nMessage 4: ",msg4)
print (f"Signature r={r2_1}, s={s4}")

print ("\nPrivate key (x1):",priv1)
print ("\nPrivate recovered (x1): ",x1rec)
print ("\nPrivate key (x2):",priv2)
print ("\nPrivate recovered (x2):",x2rec)
