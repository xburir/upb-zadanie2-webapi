
# import required module
import os
import sys
from Crypto.Cipher import AES

def encrypt_file(file_name):
    file_name_without_extension = os.path.splitext(file_name)[0]
    # opening the key
    with open(f'../public/{file_name_without_extension}.key', 'rb') as filekey:
        key = filekey.read()

    # opening the original file to encrypt
    with open('../public/'+file_name, 'rb') as file:
        original = file.read()

    # encrypt the file and generate integrity tag
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    encrypted, tag = cipher.encrypt_and_digest(original)

    # writing the integrity tag to header
    with open('../public/' + file_name, 'wb') as encrypted_file:
        encrypted_file.write(tag)
    with open('../public/'+file_name, 'a') as encrypted_file:
        encrypted_file.write('\n')

    # writing nonce to header
    with open('../public/' + file_name, 'ab') as encrypted_file:
        encrypted_file.write(nonce)
    with open('../public/'+file_name, 'a') as encrypted_file:
        encrypted_file.write('\n')

    # writing the encrypted data
    with open('../public/'+file_name, 'ab') as encrypted_file:
        encrypted_file.write(encrypted)

    # print('\n--> encryption\ntag: ', tag, '\nnonce: ', nonce, '\nencrypted: ', encrypted, '\noriginal: ', original, '\n<--\n', file=sys.stderr)





      