#!/usr/bin/env python
# -*- coding: utf-8 -*-

import serpent_ref

serpent_ref.O.show = lambda *args: None

class _serpent:
    def __init__(self,key):
        key = key.encode('hex')
        size = serpent_ref.keyLengthInBitsOf(key)
        rawKey = serpent_ref.convertToBitstring(key.lower()[::-1], size)
        self.userKey = serpent_ref.makeLongKey(rawKey)

    def encrypt(self,block):
        plainText = serpent_ref.convertToBitstring(block.encode("hex").lower()[::-1], 128)
        cipherText = serpent_ref.encrypt(plainText, self.userKey)
        return serpent_ref.bitstring2hexstring(cipherText)[::-1].decode('hex')

    def decrypt(self,block):
        cipherText = serpent_ref.convertToBitstring(block.encode("hex").lower()[::-1], 128)
        plainText = serpent_ref.decrypt(cipherText, self.userKey)
        return serpent_ref.bitstring2hexstring(plainText)[::-1].decode('hex')

class serpent_cbc:
    def __init__(self, key, iv):
        if len(iv) != 16: raise Exception, "Bad IV size"
        self.ctx = _serpent(key)
        self._state = iv

    def encrypt(self, plaintext):
        ciphertext = ""
        for i in range(0, len(plaintext), 16):
            block = ""
            for j in range(len(plaintext[i:i+16])):
                block += chr( ord(self._state[j]) ^ ord(plaintext[i+j]) )
            while len(block) < 16:
                block += self._state[len(block)]
            self._state = self.ctx.encrypt(block)
            ciphertext += self._state
        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = ""
        for i in range(0, len(ciphertext), 16):
            block = self.ctx.decrypt(ciphertext[i:i+16])
            tmp = ""
            for j in range(len(block)):
                tmp += chr( ord(self._state[j]) ^ ord(block[j]) )
            self._state = ciphertext[i:i+16]
            plaintext += tmp
        return plaintext

if __name__ == '__main__':
    ctx = _serpent("\0"*32)
    buff = ctx.encrypt("\0"*16)
    print buff.encode('hex')

    ctx = _serpent("\0"*32)
    print ctx.decrypt(buff).encode('hex'),"\n"

    ctx = serpent_cbc("\0"*32, "\0"*16)
    buff = ctx.encrypt("abcdefghijklmnopqrstuvwxyz0123456789")
    print buff.encode('hex')

    ctx = serpent_cbc("\0"*32, "\0"*16)
    print ctx.decrypt(buff)
