from Crypto.Cipher import AES
import binascii
import sys

BLOCK_SIZE = 16
key = binascii.unhexlify('00112233445566778899aabbccddeeff')
IV = binascii.unhexlify('00000000000000000000000000000000')

def pad(s):
    pad_len = BLOCK_SIZE - len(s) % BLOCK_SIZE
    if (pad_len == 0):
        pad_len = BLOCK_SIZE
    return (s + pad_len * chr(pad_len).encode('ascii'))

def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

def encrypt(key, raw):
    raw = pad(raw)
    #print binascii.hexlify(raw)
    cipher = AES.new(key, AES.MODE_ECB)
    previousCipher = binascii.unhexlify('00000000000000000000000000000000')
    ciphertext = binascii.unhexlify('00000000000000000000000000000000')

    
    num = 0
    for x in raw:
        if num==0:
            plaint = x
        else:
            plaint = plaint + x
        if num==15:
           middlePlaint = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(plaint, IV))
           ciphertext = cipher.encrypt(middlePlaint)
           previousCipher = ciphertext
           break
        num = num + 1
    num = 0 
    for x in raw:
        if num>=16:
             if (num % 16) == 0:
                 plaint = x
             else:
                 plaint = plaint + x
             if ((num+1) % 16) == 0:
                 middlePlaint = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(plaint, previousCipher))
                 previousCipher = cipher.encrypt(middlePlaint)
                 ciphertext = ciphertext +  previousCipher
        num = num + 1    
    return ciphertext  

def decrypt(key, enc):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = binascii.unhexlify('00000000000000000000000000000000')
    previousCipher = binascii.unhexlify('00000000000000000000000000000000')

    num = 0
    for x in enc:
        if num==0:
            ciphert = x
        else:
            ciphert = ciphert + x
        if num==15:
           middlePlaint = cipher.decrypt(ciphert)
           plaint = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(middlePlaint, IV))
           previousCipher = ciphert
           plaintext = plaint
           break
        num = num + 1
    num = 0 
    for x in enc:
        if num>=16:
           if (num % 16) == 0:
               ciphert = x
           else:
               ciphert = ciphert + x
           if ((num+1) % 16) == 0:
               middlePlaint = cipher.decrypt(ciphert)
               plaint = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(middlePlaint, previousCipher))
               previousCipher = ciphert
               plaintext = plaintext +  plaint
        num = num + 1    
    return unpad(plaintext)

def getopts(argv):
    opts = {}
    while argv:
        if argv[0][0] == '-':
            opts[argv[0]] = argv[1]
        argv = argv[1:]
    return opts

if __name__ == '__main__':
    myargs = getopts(sys.argv)
    if '-e' in myargs:
        plaintext = binascii.unhexlify(myargs['-e'])
        ciphertext = encrypt(key, plaintext)
        print('Ciphertext: ' +  binascii.hexlify(ciphertext))
    elif '-d' in myargs: 
        ciphertext = binascii.unhexlify(myargs['-d'])
        plaintext = decrypt(key, ciphertext)
        print('Plaintext: ' + binascii.hexlify(plaintext))
    elif '-s' in myargs:
        plaintext = binascii.a2b_qp(myargs['-s'])
        ciphertext = encrypt(key, plaintext)
        print('Ciphertext: ' + binascii.hexlify(ciphertext))
    elif '-u' in myargs:
        ciphertext = binascii.unhexlify(myargs['-u'])
        plaintext = decrypt(key, ciphertext)
        print('Plaintext: ' + binascii.b2a_qp(plaintext))
    else:
        print("python ecb.py -e 010203040506")
        print("python ecb.py -s 'this is cool'")
        print("python ecb.py -d d25a16fe349cded7f6a2f2446f6da1c2")
        print("python ecb.py -u 9b43953eeb6c3b7b7971a8bec1a90819")
