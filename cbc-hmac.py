"""
Python implementation of CBC HMAC authenticated encryption
"""

from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac


class AEAD(object):
    """
    Authenticated encryption and decryption
    """
    def __init__(self, block_len, mac_key, enc_key):
        self.block_len = block_len
        self.mac_key = mac_key
        self.enc_key = enc_key

    def authenticated_enc(self, data, aad, nonce):
        """
        Authenticated encryption
        :param data: input data
        :param aad: additional associated data
        :param nonce: nonce
        :return: c, the result of authenticated encryption
        """
        raise NotImplementedError("Must override authenticated_enc")



    def authenticated_dec(self, c, aad, nonce):
        """
        Authenticated decryption
        :param c: ciphertext
        :param aad: additional associated data
        :param nonce: nonce
        :return: decrypted data if verification succeeds, fail state else.
        """

        raise NotImplementedError("Must override authenticated_dec")


class AEAD_AES_128_CBC_HMAC_SHA_256(AEAD):
    def __init__(self, *args):
        self.block_len = 16
        self.mac_len = 16
        super(AEAD_AES_128_CBC_HMAC_SHA_256, self).__init__(self.block_len, *args)

    def __strip_padding(self, data):
        """
        Strip all padding from the data
        :param data: input data
        :return: stripped data
        """

        plainText = data
        PaddingLength = plainText[-1] #the padding is the last byte of the plain as int

        if(PaddingLength >= len(plainText)): #if the padding is longer than the plain text it cannot be valid
            raise ValueError("problematic padding")

        for i in range(PaddingLength + 1):
            if (plainText[len(plainText)-1-i] != PaddingLength):
                raise ValueError("problematic padding")
        lengthOfPaddingInPlain = PaddingLength + 1
        lengthOdPlainWithOutPadding = len(plainText) - lengthOfPaddingInPlain
        return plainText[:lengthOdPlainWithOutPadding]
    def __pad(self, data):
        """
        Pad the data so that the block size is a multiple of block_len
        :param data: input data
        :return: padded data with length an integral multiple of block_len
        """

        blockLen = self.block_len
        
        paddingLength = (blockLen - len(data)%blockLen - 1)%blockLen
        padding = bytes([paddingLength for i in range(paddingLength+1)])        
        return data + padding

    def __auth(self, data):
        """
        Call HMAC_SHA_256
        """
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(data)
        return h.finalize()

    def __encrypt(self, p, nonce):
        """
        Encrypt using AES_128_CBC
        """
        cipher = Cipher(algorithms.AES(self.enc_key), modes.CBC(nonce))
        encryptor = cipher.encryptor()
        return encryptor.update(p) + encryptor.finalize()

    def __decrypt(self, c, nonce):
        """
        Decrypt using AES_128_CBC
        """
        cipher = Cipher(algorithms.AES(self.enc_key), modes.CBC(nonce))
        decryptor = cipher.decryptor()
        return decryptor.update(c) + decryptor.finalize()

    def authenticated_enc(self, data, aad, nonce):
        """
        Authenticated encryption
        :param data: input data
        :param aad: additional associated data
        :param nonce: nonce
        :return: c, the result of authenticated encryption
        """

        concatenationOfAADAndData = aad + data

        tag = self.__auth(concatenationOfAADAndData)
        tag = tag[:16]
        concatenataionOfDataAndTag = data + tag
        plainText = self.__pad(concatenataionOfDataAndTag)

        c = self.__encrypt(plainText, nonce)
        return c


    def authenticated_dec(self, c, aad, nonce):
        """
        Authenticated decryption
        :param c: ciphertext
        :param aad: additional associated data
        :param nonce: nonce
        :return: decrypted data if verification succeeds, fail state else.
        """
        plain = self.__decrypt(c, nonce)

        dataWithoutPadding = self.__strip_padding(plain)
        
        
        lengthOfPlain = len(dataWithoutPadding)
        lengthOfData = lengthOfPlain - 16
        lengthOfTag = 16

        data = aad + dataWithoutPadding[:lengthOfData]
        tag = self.__auth(data)

        if (tag[:16] != dataWithoutPadding[lengthOfData:]): #validate the MAC
            return "FAIL"
        else:
            return dataWithoutPadding[:lengthOfData]

if __name__ == "__main__":
    data = b"hello world12351"
    aad = b"{ \xff\x1b\xca\x98\xd0\xe5\xa55\xca\xa9\xd2U\x8a8\x90K4\x90\xb2\xfa\xa9?O\x80\xea\xa2\x85\xa2ECMEo(\x1f'\x01\xf1\xa4\xd4J\x9a\xfc\xf3\x89\x93\x86\xcf"
    mac_key = b'\x9e\xdf\xdd\xb1|;\xd4\xbc\xff\x03\xb7\tZy\xef\xeb'
    enc_key = b'\xdfei\xac\x86\xa5U_r\xff\r\x1c\x8d\x02\xac\x97'
    nonce = b'T\xbaS\x87M\x9dn\xca\xe8\xb0\xcfx\x8c@W\x87'
    aead = AEAD_AES_128_CBC_HMAC_SHA_256(mac_key, enc_key)
    print(f"data = {data}")
    print(f"aad = {aad}")
    print(f"mac_key = {mac_key}")
    print(f"enc_key = {enc_key}")
    print(f"nonce = {nonce}")
    ciphertext = aead.authenticated_enc(data, aad, nonce)
    print(f"ciphertext = {ciphertext}")

    p = aead.authenticated_dec(ciphertext, aad, nonce)
    print(p)