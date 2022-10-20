
# import required module
from cryptography.fernet import Fernet
import os

def encrypt_file(file_name):
    file_name_without_extension = os.path.splitext(file_name)[0]
    # opening the key
    with open(f'../public/{file_name_without_extension}.key', 'rb') as filekey:
        key = filekey.read()
    
    # using the generated key
    fernet = Fernet(key)
    
    # opening the original file to encrypt
    with open('../public/'+file_name, 'rb') as file:
        original = file.read()
        
    # encrypting the file
    encrypted = fernet.encrypt(original)
    
    # opening the file in write mode and
    # writing the encrypted data
    with open('../public/'+file_name, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)
        
      