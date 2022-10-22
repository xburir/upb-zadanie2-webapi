
# import required module
from secrets import token_bytes
import os

def generate_key(file_name):
    # key generation
    key = token_bytes(32)

    file_name_without_extension = os.path.splitext(file_name)[0]
    
    # string the key in a file
    with open(f'../public/{file_name_without_extension}.key', 'wb') as filekey:
        filekey.write(key)
         