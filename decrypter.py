from Crypto.Cipher import AES
from random import randint


class Decrypter:
    block_iv = b'1234567890123456'

    @staticmethod
    def get_random_string(length):
        result = ""
        for i in range(length):
            result += str(randint(0, 9))
        return result

    @staticmethod
    def apply_padding(string, size, fill_value):
        while len(string) < size:
            string += fill_value
        return string

    @staticmethod
    def xor_arrays(source, dest):
        if type(source) == str:
            source = bytearray(source.encode('utf8'))
        if type(dest) == str:
            dest = bytearray(dest.encode('utf8'))
        result = bytearray()
        for item1, item2 in zip(source, dest):
            result.append(item1 ^ item2)
        return result

    @staticmethod
    def simulate_aes_cbc_decryption(encrypted_blocks, key, iv):
        key = bytearray(key.encode('utf8'))
        result = ''
        aes_decrypter = AES.new(key, AES.MODE_CBC, Decrypter.block_iv)
        for i, encrypted_block in enumerate(encrypted_blocks):
            block = aes_decrypter.decrypt(encrypted_block)
            if i == 0:
                plain_text_block = Decrypter.xor_arrays(block, iv)
            else:
                plain_text_block = Decrypter.xor_arrays(block, encrypted_blocks[i - 1])
            result += str(plain_text_block.decode('utf8').strip())
        return result

    @staticmethod
    def simulate_aes_cfb_decryption(encrypted_blocks, key, iv):
        key = bytearray(key.encode('utf8'))
        result = ''
        aes_decrypter = AES.new(key, AES.MODE_CFB, Decrypter.block_iv)
        for i, encrypted_block in enumerate(encrypted_blocks):
            if i == 0:
                if type(iv) == str:
                    iv = bytes(iv.encode('uft8'))
                tmp = aes_decrypter.encrypt(iv)
                plain_text_block = Decrypter.xor_arrays(tmp, encrypted_block)
            else:
                tmp = aes_decrypter.encrypt(bytes(encrypted_blocks[i - 1]))
                plain_text_block = Decrypter.xor_arrays(tmp, encrypted_block)
            result += str(plain_text_block.decode('utf8').strip())
        return result
