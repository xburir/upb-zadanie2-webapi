
# import required module
from cryptography.fernet import Fernet
import os

def generate_key(file_name):
    # key generation
    key = Fernet.generate_key()

    file_name_without_extension = os.path.splitext(file_name)[0]
    
    # string the key in a file
    with open(f'../public/{file_name_without_extension}.key', 'wb') as filekey:
        filekey.write(key)
         