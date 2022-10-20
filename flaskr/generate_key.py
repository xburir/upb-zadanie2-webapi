
# import required module
from cryptography.fernet import Fernet

def generate_key():
    # key generation
    key = Fernet.generate_key()

    print(key)
    
    # string the key in a file
    with open('filekey.key', 'wb') as filekey:
        filekey.write(key)
         