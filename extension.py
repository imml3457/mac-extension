import hashlib
from math import ceil
import os
#getting the padding and everything on the 
def sha1pad(data, bytelength = 0):
    bytes = ""
    i = 0
    for n in range(len(data)):
        #formatting data into byte array
        #formatted as bits
        bytes+='{0:08b}'.format(ord(data[n]))

    #adding final bit
    #which starts the 1 for padding
    bits = bytes+"1"
    padBits = bits
    #getting how many 0's for padding
    while len(padBits)%512 != 448:
        padBits+="0"
        i += 1
    #append the original length to the end
    if bytelength != 0:
        padBits+='{0:064b}'.format((len(bits)-1) + bytelength+512)
    else:
        padBits+='{0:064b}'.format((len(bits)-1))
    return padBits

def sha1(data, msglength):

    #given 32 bit words from FIPS
    h0 = 0xac94e7cf
    h1 = 0x99456fbf
    h2 = 0xe5e7aa79
    h3 = 0xe94d8905
    h4 = 0x7889b67e

    padBits = sha1pad(data, msglength)
    #parsing into chunks
    #also required functions below
    def chunks(l, n):
        return [l[i:i+n] for i in range(0, len(l), n)]

    def rotl(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff
    
    def Ch(x, y, z):
        return (x & y) | ((~x) & z)
    
    def parity(x, y, z):
        return x ^ y ^ z
    
    def maj(x, y, z):
        return (x & y) | (x & z) | (y & z)
    #step 1 in FIPS
    for c in chunks(padBits, 512): 
        words = chunks(c, 32)
        w = [0]*80
        for n in range(0, 16):
            w[n] = int(words[n], 2)
        for i in range(16, 80):
            w[i] = rotl((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)  
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        #taken directly from FIPS section 4.2.1
        for i in range(0, 80):
            if 0 <= i <= 19:
                #ch function
                f = Ch(b, c, d)
                k = 0x5a827999
            elif 20 <= i <= 39:
                #parity
                f = parity(b, c, d)
                k = 0x6ed9eba1
            elif 40 <= i <= 59:
                #maj
                f = maj(b, c, d)
                k = 0x8f1bbcdc
            elif 60 <= i <= 79:
                #parity again
                f = parity(b, c, d)
                k = 0xca62c1d6

            temp = rotl(a, 5) + f + e + k + w[i] & 0xffffffff
            e = d
            d = c
            c = rotl(b, 30)
            b = a
            a = temp
        #calculate the intermediate hash and use a full bit mask
        h0 = a + h0 & 0xffffffff
        h1 = b + h1 & 0xffffffff
        h2 = c + h2 & 0xffffffff
        h3 = d + h3 & 0xffffffff
        h4 = e + h4 & 0xffffffff
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

#text for the algorithm
extendedmsg = ""
original = ""
tempkey = "aaaaaaaaaaaaaaaa"
#need to pad with a temporary key to ensure proper padding
#we know the size, so just any string can work
padding = hex(int(sha1pad(tempkey + original), 2))[(len(tempkey) + len(original)) * 2 + 2:]
hexoriginal = ''.join(hex(ord(c))[2:] for c in original)
hexextended = ''.join(hex(ord(c))[2:] for c in extendedmsg)
# construction of deceptive text
print(hexoriginal + padding + hexextended)

#print the extended MAC
print(sha1(extendedmsg, len(sha1pad(""))))


