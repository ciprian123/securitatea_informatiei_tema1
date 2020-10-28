import socket
import pickle
import os.path as path

from encryptor import Encryptor
from decrypter import Decrypter


secret_key3 = '1111222233334444'
iv_k3 = b'1002492919392444'

soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.connect(("127.0.0.1", 6969))

encryption_mode = input('Enter encryption mode: `CBC` or `CFB`: ')
while encryption_mode.lower() not in ['cbc', 'cfb']:
    encryption_mode = input('Enter encryption mode: `CBC` or `CFB`: ')

soc.sendall(bytes(encryption_mode.encode('utf8')))

# receive the encryption mode used, encrypted key and encrypted iv
response = soc.recv(1024)
encrypted_data = pickle.loads(response)

# client a already knows encryption mode, doesn't need to extract it
encrypted_key = encrypted_data[1]
encrypted_iv_k1 = encrypted_data[2]

if encryption_mode == 'cbc':
    decrypted_key1 = Decrypter.simulate_aes_cbc_decryption([encrypted_key], secret_key3, iv_k3)
    decrypted_iv_k1 = Decrypter.simulate_aes_cbc_decryption([encrypted_iv_k1], secret_key3, iv_k3)
else:
    decrypted_key1 = Decrypter.simulate_aes_cfb_decryption([encrypted_key], secret_key3, iv_k3)
    decrypted_iv_k1 = Decrypter.simulate_aes_cfb_decryption([encrypted_iv_k1], secret_key3, iv_k3)

# sending the encrypted key back for confirmation
if encryption_mode == 'cbc':
    encrypted_key_to_confirm = Encryptor.simulate_aes_cbc_encryption(decrypted_key1, secret_key3, iv_k3)[0]
else:
    encrypted_key_to_confirm = Encryptor.simulate_aes_cfb_encryption(decrypted_key1, secret_key3, iv_k3)[0]

confirmation_message = pickle.dumps(encrypted_key_to_confirm)
soc.sendall(confirmation_message)

message = soc.recv(128).decode('utf8')
print(message)

# encrypting and sending the file in blocks
file_name = input('[Client A] Enter file name you want to encrypt and send: ')
while not path.exists(file_name):
    print(f'[Client A] The file {file_name} does not exists. Try again...')
    file_name = input('[Client A] Enter file name you want to encrypt and send: ')

file_content = ''
with open(file_name) as file:
    for line in file.readlines():
        file_content += line

if encryption_mode == 'cbc':
    encrypted_blocks = Encryptor.simulate_aes_cbc_encryption(file_content, decrypted_key1, decrypted_iv_k1)
else:
    encrypted_blocks = Encryptor.simulate_aes_cfb_encryption(file_content, decrypted_key1, decrypted_iv_k1)

# send to server number of blocks and each block
no_of_blocks = len(encrypted_blocks)
if encryption_mode == 'cbc':
    encrypted_counter = Encryptor.simulate_aes_cbc_encryption(str(no_of_blocks), decrypted_key1, decrypted_iv_k1)
else:
    encrypted_counter = Encryptor.simulate_aes_cfb_encryption(str(no_of_blocks), decrypted_key1, decrypted_iv_k1)

response = pickle.dumps([encrypted_counter, encrypted_blocks])
soc.sendall(response)


print('[Client A] File encryption transfer complete!')
