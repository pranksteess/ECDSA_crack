import ecdsa
import random
import libnum
import olll
import hashlib
import sys

# https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
 
G = ecdsa.NIST256p.generator
order = G.order()

print ("Curve detail")
print (G.curve())
print ("Order:", hex(order))
print ("Gx:",hex(G.x()))
print ("Gy:",hex(G.y()))


priv = random.randrange(1,order)
 
Public_key = ecdsa.ecdsa.Public_key(G, G * priv)
Private_key = ecdsa.ecdsa.Private_key(Public_key, priv)
 
k1 = random.randrange(1, pow(2,127))
k2 = random.randrange(1, pow(2,127))

msg1="Hello"
msg2="Hello1"

if (len(sys.argv)>1):
	msg1=(sys.argv[1])
if (len(sys.argv)>2):
	msg2=(sys.argv[2])

m1 = int(hashlib.sha256(msg1.encode()).hexdigest(),base=16)
m2 = int(hashlib.sha256(msg2.encode()).hexdigest(),base=16)
 
sig1 = Private_key.sign(m1, k1)
sig2 = Private_key.sign(m2, k2)

print ("\nMessage 1: ",msg1)
print ("Message 2: ",msg2)
print ("\nSig 1 r,s: ",sig1.r,sig1.s)
print ("Sig 2 r,s: ",sig2.r,sig2.s)
print ("\nk1: ",k1)
print ("k2: ",k2)

print ("Private key: ",priv)

r1 = sig1.r
s1_inv = libnum.invmod(sig1.s, order)
r2 = sig2.r
s2_inv = libnum.invmod(sig2.s, order)
 
matrix = [[order, 0, 0, 0], [0, order, 0, 0],
[r1*s1_inv, r2*s2_inv, (2**128) / order, 0],
[m1*s1_inv, m2*s2_inv, 0, 2**128]]
 
search_matrix = olll.reduction(matrix, 0.75)
r1_inv = libnum.invmod(sig1.r, order)
s1 = sig1.s
 
for search_row in search_matrix:
	possible_k1 = search_row[0]
	try_private_key = (r1_inv * ((possible_k1 * s1) - m1)) % order
 
	if ecdsa.ecdsa.Public_key(G, G * try_private_key) == Public_key:
		print("\nThe private key has been found")
		print (try_private_key)
