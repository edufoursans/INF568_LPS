import math
import random
from os.path import isfile

# converts an integer to a list of bits of size 8
def inttobits(n):
	return [((n>>i)&1) for i in range(8)]

# convert a string to a list of bits
def stringtobits(s):
	s = s.encode('utf8')
	return [inttobits(x)[i] for x in s for i in range(8)]

# convert a list of 8 bits to an integer
def bitstoint(bitlist):
	out = 0
	for bit in bitlist[::-1]:
		out = (out << 1) | bit
	return out

# convert a list of bits to a string
def bitlisttostring(B):
	return ''.join([chr(bitstoint(B[8*i:8*(i+1)]))  for i in range(len(B)//8)])

# compute modulo in Z/q with correct representation
def mod(x,q):
	return (x % q) - (q if ((x % q) > q//2) else 0)

# pick a random integer in Z/q with correct representation
def rand_in_zqz(q):
	return random.randint(mod(1 + (q//2),q),q//2)

# the special product which is the basis for the scheme
def special_product(A,s,q):
	assert len(A[0]) == len(s)
	m = len(A)
	n = len(s)
	qm = pow(q,m)
	sum = 0
	for j in range(n):
		for k in range(m):
			sum += s[j] * A[k][j] * (pow(q,k,qm))
			sum %= qm
	t = [0 for i in range(m)]
	curr = q
	for i in range(m):
		t[i] = (sum % curr) * q // curr
		sum -= t[i]
		t[i] = mod(t[i],q)
		curr *= q
	return t

# an object which stores a public and/or a private key, which can then be called to encrypt/decrypt messages
class LPS:

	# generate a private/public key pair
	def key_gen(self,n,q,k):
		assert q > 10 * n * (math.log(n))**2
		assert q%2 == 1 #"For simplicity, we will assume that q is odd, but our results follow for all q with minimal changes." (https://eprint.iacr.org/2009/576.pdf)
		self.q = q
		self.k = k
		self.n = n
		Aprime = [[0 for i in range(n)] for j in range(n)]
		for i in range(n):
			for j in range(n):
				Aprime[i][j] = rand_in_zqz(q)
		s= [[random.randint(0,1) for i in range(n)] for j in range(k)]
		t = []
		for i in range(k):
			t.append(special_product(Aprime,s[i],q))
		self.A = [[(Aprime[i][j] if (j<n) else t[j-n][i]) for j in range(n+k)] for i in range(n)]
		self.tA = [[self.A[i][j] for i in range(n)] for j in range(n+k)]
		self.s = s

	# the low level encryption function operates on arrays of bits
	def enc_low(self,m):
		assert self.k == len(m)
		r = [random.randint(0,1) for i in range(self.n)]
		t = special_product(self.tA,r,self.q)
		return [mod((t[i] + (0 if (i<self.n) else (m[i-self.n]*((self.q)-1)//2))),self.q) for i in range(self.n+self.k)]

	# the low level decryption function operates on arrays of bits
	def dec_low(self,u):
		assert len(u) == self.n + self.k
		v = [u[i] for i in range(self.n)]
		w = [u[self.n + i] for i in range(self.k)]
		m = []
		for i in range(self.k):
			y = sum([v[j]*self.s[i][j] for j in range(self.n)]) - w[i]
			y = mod(y,self.q)
			if ((y if y>0 else -y) < self.q/4):
				m.append(0)
			else:
				m.append(1)
		return m

	# encrypt a string
	def enc(self,mstring):
		return self.enc_low(stringtobits(mstring))

	# decrypt to a string
	def dec(self,u):
		return bitlisttostring(self.dec_low(u))

	# encrypt from a file
	def encf(self,file):
		with open(file,'r') as f:
			return self.enc(f.read())

	# decrypt from a file
	def decf(self,file):
		with open(file,'r') as f:
			return self.dec([int(x) for x in f.read().split()])

	# encrypt from a string or file to a file
	def enc_to_file(self,m_or_file,file):
		if(isfile(m_or_file)):
			with open(m_or_file,'r') as g:
				m_or_file = g.read()
		f = open(file,'w')
		f.write(' '.join([str(x) for x in self.enc(m_or_file)]))
		f.close()

	# encrypt from a list or file to a file
	def dec_to_file(self,u_or_file,file):
		if(isfile(u_or_file)):
			with open(u_or_file,'r') as g:
				u_or_file = [int(x) for x in g.read().split()]
		f = open(file,'w')
		f.write(''.join(self.dec(u_or_file)))
		f.close()

	# import a public key from a file
	def import_public(self,file):
		with open(file,'r') as f:
			f.readline()
			self.n = int(f.readline())
			self.k = int(f.readline())
			self.q = int(f.readline())
			self.A = []
			for i in range(self.n):
				self.A.append(f.readline().split())
			self.tA = [[self.A[i][j] for i in range(self.n)] for j in range(self.n+self.k)]

	# import a secret key from a file
	def import_private(self,file):
		with open(file,'r') as f:
			f.readline()
			self.n = int(f.readline())
			self.k = int(f.readline())
			self.s = []
			for i in range(self.k):
				self.s.append([int(x) for x in f.readline().split()])

	# export a public key to a file
	def export_public(self,file):
		with open(file,'w') as f:
			f.write("PUBLIC KEY with n = "+str(self.n)+" , k = "+str(self.k)+" and q = "+str(self.q)+".\n")
			f.write(str(self.n)+"\n")
			f.write(str(self.k)+"\n")
			f.write(str(self.q)+"\n")
			for i in range(self.n):
				f.write((' '.join([str(x) for x in self.A[i]]))+"\n")

	# export a private key to a file
	def export_private(self,file):
		with open(file,'w') as f:
			f.write("PRIVATE KEY with n = "+str(self.n)+" and k = "+str(self.k)+".\n")
			f.write(str(self.n)+"\n")
			f.write(str(self.k)+"\n")
			for i in range(self.k):
				f.write((' '.join([str(x) for x in self.s[i]]))+"\n")
