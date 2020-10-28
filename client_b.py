import socket
import pickle

from encryptor import Encryptor
from decrypter import Decrypter

secret_key3 = '1111222233334444'
iv_k3 = b'1002492919392444'

soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.connect(("127.0.0.1", 6969))

print('Please wait for client A to choose... ')
encryption_mode = soc.recv(2048).decode('utf8')
while encryption_mode == '':
    encryption_mode = soc.recv(2048).decode('utf8')
encryption_mode = soc.recv(2048).decode('utf8')

if encryption_mode == 'cbc':
    print('Your encryption mode is cfb!')
else:
    print('Your encryption mode is cbc!')

# receive the encryption mode used, encrypted key and encrypted iv
response = soc.recv(2048)
encrypted_data = pickle.loads(response)

encryption_mode = encrypted_data[0]
encrypted_key2 = encrypted_data[1]
encrypted_iv_k2 = encrypted_data[2]

if encryption_mode == 'cfb':
    decrypted_key2 = Decrypter.simulate_aes_cbc_decryption([encrypted_key2], secret_key3, iv_k3)
    decrypted_iv_k2 = Decrypter.simulate_aes_cbc_decryption([encrypted_iv_k2], secret_key3, iv_k3)
else:
    decrypted_key2 = Decrypter.simulate_aes_cfb_decryption([encrypted_key2], secret_key3, iv_k3)
    decrypted_iv_k2 = Decrypter.simulate_aes_cfb_decryption([encrypted_iv_k2], secret_key3, iv_k3)

decrypted_iv_k2 = bytes(decrypted_iv_k2.encode('utf8'))

# sending the encrypted key back for confirmation
if encryption_mode == 'cfb':
    encrypted_key_to_confirm = Encryptor.simulate_aes_cbc_encryption(decrypted_key2, secret_key3, iv_k3)[0]
else:
    encrypted_key_to_confirm = Encryptor.simulate_aes_cfb_encryption(decrypted_key2, secret_key3, iv_k3)[0]

confirmation_message = pickle.dumps(encrypted_key_to_confirm)
soc.sendall(confirmation_message)

message = soc.recv(128).decode('utf8')
print(message)

print('[CLIENT B] Receiving data... ')
message = soc.recv(20480000)


decoded_message = pickle.loads(message)
if encryption_mode == 'cfb':
    blocks_counter = Decrypter.simulate_aes_cbc_decryption([decoded_message[0]], decrypted_key2, decrypted_iv_k2)
    block_list = Decrypter.simulate_aes_cbc_decryption(decoded_message[1], decrypted_key2, decrypted_iv_k2)
else:
    blocks_counter = Decrypter.simulate_aes_cfb_decryption([decoded_message[0]], decrypted_key2, decrypted_iv_k2)
    block_list = Decrypter.simulate_aes_cfb_decryption(decoded_message[1], decrypted_key2, decrypted_iv_k2)

print('No of blocks: ', blocks_counter)
print('File contents: \n')
for _ in block_list:
    print(_, end='')

print('\n\n[CLIENT B] Data decrypted successfully!')
