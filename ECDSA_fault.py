# same k, different G

import ecdsa
import random
import libnum
import hashlib
import sys


G = ecdsa.SECP256k1.generator
order = G.order()

priv1 = random.randrange(1,order)
 
Public_key = ecdsa.ecdsa.Public_key(G, G * priv1)
d = ecdsa.ecdsa.Private_key(Public_key, priv1)

k = random.randrange(1, 2**127)

msg="Hello"

if (len(sys.argv)>1):
	msg=(sys.argv[1])



h = int(hashlib.sha256(msg.encode()).hexdigest(),base=16)
sig = d.sign(h, k)


r,s = sig.r,sig.s

# Now generate a fault
rf = sig.r+1
sf=(libnum.invmod(k,order)*(h+priv1*rf)) % order

k = h*(s-sf) * libnum.invmod(sf*r-s*rf,order)


valinv = libnum.invmod( (sf*r-s*rf),order)

dx =(h*(s-sf)* valinv) % order

print(f"Message: {msg}")
print(f"k: {k}")

print(f"Sig 1 (Good): r={r}, s={s}")
print(f"Sig 2 (Faulty): r={rf}, s={sf}")

print (f"\nGenerated private key: {priv1}")
print (f"\nRecovered private key: {dx}")
