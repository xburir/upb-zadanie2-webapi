# import required module
import os
import sys
from Crypto.Cipher import AES
from os import path
from flask import session

def encrypt_file(file_name, AES_encrypted, AES_key, target):
    file_name_without_extension = os.path.splitext(file_name)[0]

    # opening the original file to encrypt
    with open('../public/'+file_name, 'rb') as file:
        original = file.read()

    # encrypt the file and generate integrity tag
    cipher = AES.new(AES_key, AES.MODE_EAX)
    nonce = cipher.nonce
    encrypted, tag = cipher.encrypt_and_digest(original)

    # writing the integrity tag to header 
    with open('../public/' + file_name, 'wb') as encrypted_file:
        encrypted_file.write(tag)
    with open('../public/'+file_name, 'a') as encrypted_file:
        encrypted_file.write(',,')
    
    with open('../files/'+target+'/'+file_name,'wb') as saved_file:
        saved_file.write(tag)
    with open('../files/'+target+'/'+file_name,'a') as saved_file:
        saved_file.write(',,')

    # writing nonce to header 
    with open('../public/' + file_name, 'ab') as encrypted_file:
        encrypted_file.write(nonce)
    with open('../public/'+file_name, 'a') as encrypted_file:
        encrypted_file.write(',,')

    with open('../files/'+target+'/'+file_name,'ab') as saved_file:
        saved_file.write(nonce)
    with open('../files/'+target+'/'+file_name,'a') as saved_file:
        saved_file.write(',,')

    #write encrypted AES key to header
    with open('../public/' + file_name, 'ab') as encrypted_file:
        encrypted_file.write(AES_encrypted)
    with open('../public/'+file_name, 'a') as encrypted_file:
        encrypted_file.write(',,')

    with open('../files/'+target+'/'+file_name,'ab') as saved_file:
        saved_file.write(AES_encrypted)
    with open('../files/'+target+'/'+file_name,'a') as saved_file:
        saved_file.write(',,')
    

    # writing the encrypted data 
    with open('../public/'+file_name, 'ab') as encrypted_file:
        encrypted_file.write(encrypted)

    
    with open('../files/'+target+'/'+file_name,'ab') as saved_file:
        saved_file.write(encrypted)

    print('\n--> encryption\ntag: ', tag,'\nAES_key', AES_key, '\nAES_encrypted: ', AES_encrypted, '\nnonce: ', nonce, '\nencrypted: ', encrypted, '\noriginal: ', original, '\n<--\n', file=sys.stderr)
    print("Length of bytes of AES_KEY: ", len(AES_key), file=sys.stderr)
    print("Length of bytes of AES_KEY_ENCRYPTED: ", len(AES_encrypted), file=sys.stderr)
    print("AES_DECRYPTED DATA TYPE: ", type(AES_key), file=sys.stderr)
    