# import required module
import os
import sys
import random
import string

def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def generate_key(file_name):
    #key=b'rv6LuL6GPeiXOS9A'
    key=get_random_string(32).encode('UTF-8')

    print("VYGENEROVANY AES KLUC: ", key, file=sys.stderr)
    print("Length of bytes of AES_KEY: ", len(key), file=sys.stderr)
    print("AES_DECRYPTED DATA TYPE: ", type(key), file=sys.stderr)

    file_name_without_extension = os.path.splitext(file_name)[0]
    
    # string the key in a file
    #with open(f'../public/{file_name_without_extension}.key', 'wb') as filekey:
    #   filekey.write(key)

    return key