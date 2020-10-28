from Crypto.Cipher import AES
from random import randint


class Encryptor:
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
    def simulate_aes_cfb_encryption(data, key, iv):
        """ Order: encrypt iv, xor result with plain text, iv becomes encryption """
        key = bytearray(key.encode('utf8'))
        tmp_text = iv
        start = 0
        end = 16
        encrypted_blocks = []
        aes_encryptor = AES.new(key, AES.MODE_CFB, Encryptor.block_iv)
        if len(data) < 16:
            data = Encryptor.apply_padding(data, 16, ' ')
        while start < len(data):
            plain_text_block = data[start:end]
            if len(plain_text_block) < 16:
                plain_text_block = Encryptor.apply_padding(plain_text_block, 16, ' ')
            if type(tmp_text) == str:
                tmp_text = tmp_text.encode('utf8')
            tmp_text = bytearray(tmp_text)

            encrypted_block_cipher = aes_encryptor.encrypt(tmp_text)
            encrypted_block_cipher = Encryptor.xor_arrays(plain_text_block, encrypted_block_cipher)
            encrypted_blocks.append(bytes(encrypted_block_cipher))

            tmp_text = encrypted_block_cipher
            start = end
            end = min(end + 16, len(data))

        return encrypted_blocks

    @staticmethod
    def simulate_aes_cbc_encryption(_data, key, iv):
        """ Order: xor iv and plain text, encrypt result, iv becomes encryption """
        key = bytearray(key.encode('utf8'))
        tmp_text = iv
        start = 0
        end = 16
        encrypted_blocks = []
        aes_encryptor = AES.new(key, AES.MODE_CBC, Encryptor.block_iv)
        if len(_data) < 16:
            _data = Encryptor.apply_padding(_data, 16, ' ')
        while start < len(_data):
            plain_text_block = _data[start:end]
            if len(plain_text_block) < 16:
                plain_text_block = Encryptor.apply_padding(plain_text_block, 16, ' ')
            if type(tmp_text) == str:
                tmp_text = tmp_text.encode('utf8')
            tmp_text = bytes(tmp_text)
            xor_tmp = Encryptor.xor_arrays(plain_text_block, tmp_text)

            encrypted_block_cipher = aes_encryptor.encrypt(xor_tmp)
            encrypted_blocks.append(encrypted_block_cipher)

            tmp_text = encrypted_block_cipher
            start = end
            end = min(end + 16, len(_data))
        return encrypted_blocks
