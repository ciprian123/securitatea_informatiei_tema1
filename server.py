import sys
import socket
import pickle
from random import randint

from threading import Thread
from encryptor import Encryptor
from decrypter import Decrypter

def get_random_string(n):
    digits = "0123456789"
    string = ""
    for i in range(n):
        string += (digits[randint(0, 9)])
    return bytes(string.encode('utf8'))


secret_key3 = '1111222233334444'
iv_k3 = b'1002492919392444'

secret_key2 = '1122334455667788'
iv_k2 = get_random_string(16)

secret_key1 = '1234567890123456'
iv_k1 = get_random_string(16)

client_a_enc_mode = ''
encrypted_message_pickle = ''


def client_a_thread(conn, ip, port):
    global client_a_enc_mode, encrypted_message_pickle
    encryption_mode = conn.recv(128).decode('utf8')

    if encryption_mode.lower() == 'cbc':
        client_a_enc_mode = 'cbc'
        encrypted_key = Encryptor.simulate_aes_cbc_encryption(secret_key1, secret_key3, iv_k3)[0]
        encrypted_iv_k1 = Encryptor.simulate_aes_cbc_encryption(iv_k1, secret_key3, iv_k3)[0]
    else:
        client_a_enc_mode = 'cfb'
        encrypted_key = Encryptor.simulate_aes_cfb_encryption(secret_key1, secret_key3, iv_k3)[0]
        encrypted_iv_k1 = Encryptor.simulate_aes_cfb_encryption(iv_k1, secret_key3, iv_k3)[0]

    response = pickle.dumps([encryption_mode, encrypted_key, encrypted_iv_k1])
    conn.sendall(response)

    # receive encrypted key as confirmation message
    data = conn.recv(128)
    encrypted_key_to_confirm = pickle.loads(data)
    if encryption_mode == 'cbc':
        key_to_confirm = Decrypter.simulate_aes_cbc_decryption([encrypted_key_to_confirm], secret_key3, iv_k3)
    else:
        key_to_confirm = Decrypter.simulate_aes_cfb_decryption([encrypted_key_to_confirm], secret_key3, iv_k3)
    print('[Client A] send confirmation key: ', key_to_confirm)
    if key_to_confirm == secret_key1:
        print('Key is valid!')

        # send confirmation for secure communication
        conn.sendall('[SERVER] Secure connection established!'.encode('utf'))
    else:
        print('Key is invalid!')
        conn.sendall('[SERVER] Secure connection cannot be established!'.encode('utf'))

    response = conn.recv(20480000)
    decoded_response = pickle.loads(response)

    if encryption_mode == 'cbc':
        decrypted_counter = Decrypter.simulate_aes_cbc_decryption(decoded_response[0], secret_key1, iv_k1)
        decrypted_file_content = Decrypter.simulate_aes_cbc_decryption(decoded_response[1], secret_key1, iv_k1)
    else:
        decrypted_counter = Decrypter.simulate_aes_cfb_decryption(decoded_response[0], secret_key1, iv_k1)
        decrypted_file_content = Decrypter.simulate_aes_cfb_decryption(decoded_response[1], secret_key1, iv_k1)

    print('[SERVER] Decrypted file content:')
    print(decrypted_file_content)

    # encrypting data and sending it to client b
    if encryption_mode == 'cbc':
        encrypted_counter = Encryptor.simulate_aes_cfb_encryption(decrypted_counter, secret_key2, iv_k2)[0]
        encrypted_content = Encryptor.simulate_aes_cfb_encryption(decrypted_file_content, secret_key2, iv_k2)
    else:
        encrypted_counter = Encryptor.simulate_aes_cbc_encryption(decrypted_counter, secret_key2, iv_k2)[0]
        encrypted_content = Encryptor.simulate_aes_cbc_encryption(decrypted_file_content, secret_key2, iv_k2)

    encrypted_message_pickle = pickle.dumps([encrypted_counter, encrypted_content])


def client_b_thread(conn, ip, port):
    global client_a_enc_mode, encrypted_message_pickle
    conn.sendall(bytes(client_a_enc_mode.encode('utf8')))
    while client_a_enc_mode == '':
        conn.sendall(bytes(client_a_enc_mode.encode('utf8')))
    conn.sendall(bytes(client_a_enc_mode.encode('utf8')))
    conn.sendall(bytes(client_a_enc_mode.encode('utf8')))
    if client_a_enc_mode == 'cbc':
        # if client a uses cbc, client b will use cfb, and vice versa
        encrypted_key = Encryptor.simulate_aes_cfb_encryption(secret_key2, secret_key3, iv_k3)[0]
        encrypted_iv_k2 = Encryptor.simulate_aes_cfb_encryption(iv_k2, secret_key3, iv_k3)[0]
    else:
        encrypted_key = Encryptor.simulate_aes_cbc_encryption(secret_key2, secret_key3, iv_k3)[0]
        encrypted_iv_k2 = Encryptor.simulate_aes_cbc_encryption(iv_k2, secret_key3, iv_k3)[0]

    response = pickle.dumps([client_a_enc_mode, encrypted_key, encrypted_iv_k2])
    conn.sendall(response)

    # receive encrypted key as confirmation message
    data = conn.recv(2048)
    encrypted_key_to_confirm = pickle.loads(data)
    if client_a_enc_mode == 'cbc':
        key_to_confirm = Decrypter.simulate_aes_cfb_decryption([encrypted_key_to_confirm], secret_key3, iv_k3)
    else:
        key_to_confirm = Decrypter.simulate_aes_cbc_decryption([encrypted_key_to_confirm], secret_key3, iv_k3)
    print('[Client B] send confirmation key: ', key_to_confirm)
    if key_to_confirm == secret_key2:
        print('Key is valid!')

        # send confirmation for secure communication
        conn.sendall('[SERVER] Secure connection established!'.encode('utf'))
    else:
        print('Key is invalid!')
        conn.sendall('[SERVER] Secure connection cannot be established!'.encode('utf'))

    # send encrypted contend to client b
    while encrypted_message_pickle == '':
        pass
    conn.sendall(encrypted_message_pickle)
    print('[SERVER] Encrypted data send successfully!')


def start_server():
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # this is for easy starting/killing the app
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('Socket created')

    try:
        soc.bind(("127.0.0.1", 6969))
        print('Socket bind complete')
    except socket.error as msg:
        print('Bind failed. Error : ' + str(sys.exc_info()))
        sys.exit()

    soc.listen(2)
    print('Socket now listening...')

    conn_client_a, addr_client_a = soc.accept()
    conn_client_b, addr_client_b = soc.accept()

    ip_client_a, port_client_a = str(addr_client_a[0]), str(addr_client_a[1])
    ip_client_b, port_client_b = str(addr_client_a[0]), str(addr_client_a[1])

    print('Accepting connection from: ' + ip_client_a + ':' + port_client_a)
    print('Accepting connection from: ' + ip_client_b + ':' + port_client_b)

    Thread(target=client_a_thread, args=(conn_client_a, ip_client_a, port_client_a)).start()
    Thread(target=client_b_thread, args=(conn_client_b, ip_client_b, port_client_b)).start()


start_server()
