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
    return plaintext

def paddingOracle(preEnc, enc):
    cipher = AES.new(key, AES.MODE_ECB)
    middlePlaint = cipher.decrypt(enc)
    plaint = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(middlePlaint, preEnc))
    pad = True
    length = len(plaint) - len(unpad(plaint))
    paded = plaint[-ord(plaint[len(plaint)-1:]):]
    for x in paded:
        if ord(x) == length:
            continue
        else:
            pad = False
    return pad
    
def attackResult(preEnc, enc):
    changeIV = preEnc
    cipher = AES.new(key, AES.MODE_ECB)
    DK  = []
    
    for j in range(16):
        p = j + 1
        for i in range(256):
            x = format(i, '02x')
            newIV = binascii.unhexlify('00000000000000000000000000000000')
            if p==1:
                newIV = changeIV[:-p] + binascii.unhexlify(x)
            elif p==16:
                newIV = binascii.unhexlify(x) + changeIV[(-p+1):]
            else:
                newIV = changeIV[:-p] + binascii.unhexlify(x) + changeIV[(-p+1):]
            flag = paddingOracle(newIV, enc)
            if flag and p==16:
                d = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(newIV[-p], binascii.unhexlify(format(16, '02x'))))
                DK.append(d)
            if flag and p<16:
                h = False
                for k in range(256):
                    y = format(k, '02x')
                    s = newIV[:(-p-1)] + binascii.unhexlify(y) + newIV[-p:] 
                    if paddingOracle(s, enc)==False:
                        h = True
                        break
                if h==True:
                    continue  #we must find the changeIV, which can make the padding correct
                else:
                    d = ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(newIV[-p], binascii.unhexlify(format(p, '02x'))))
                    DK.append(d)
                    changeIV = newIV[:-p] + ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(DK[::-1], binascii.unhexlify(p*format(p+1, '02x'))))
    
    plaintext=''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(DK[::-1], preEnc))
    return plaintext


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
        print('Plaintext: ' + binascii.b2a_qp(unpad(plaintext)))
    elif '-o' in myargs:
        ciphertext = binascii.unhexlify(myargs['-o'])
        haha= paddingOracle(IV, ciphertext)
        print haha
    elif '-as' in myargs:
        ciphertext = binascii.unhexlify(myargs['-as'])
        num = 0
        for x in ciphertext:
            if num==0:
               ciphert = x
            else:
               ciphert = ciphert + x
            num = num + 1
            if num==16:
                break
        plaintext = attackResult(IV, ciphert)
        print('First block of ciphertext is: ' +binascii.b2a_qp(plaintext))
    elif '-aas' in myargs:
        ciphertext = binascii.unhexlify(myargs['-aas'])
        ci = []
        num = 0
        for x in ciphertext:
            if (num%16)==0:
                ciphert = x
            else:
                if ((num+1)%16)==0:
                    ciphert = ciphert + x
                    if num==15:
                        preCipher = IV
                    plaintext = attackResult(preCipher, ciphert)
                    preCipher = ciphert
                    if (num+1) == len(ciphertext):
                        plaintext = unpad(plaintext)
                    ci.append(binascii.b2a_qp(plaintext))
                else:
                    ciphert = ciphert + x
            num = num + 1

        print('ciphertext of using padding oracle is: ')
        print ''.join([x for x in ci])
    else:
        print("python ecb.py -e 010203040506")
        print("python ecb.py -s 'this is cool'")
        print("python ecb.py -d d25a16fe349cded7f6a2f2446f6da1c2")
        print("python ecb.py -u 9b43953eeb6c3b7b7971a8bec1a90819")
