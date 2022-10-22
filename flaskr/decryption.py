
# import required module
from cryptography.fernet import Fernet

def decrypt_file(file_filename, key_filename):
    # opening the key
    with open(f'../public/decryption/{key_filename}', 'rb') as filekey:
        key = filekey.read()
        
    # using the key
    fernet = Fernet(key)
    
    # opening the encrypted file
    with open('../public/decryption/'+file_filename, 'rb') as enc_file:
        encrypted = enc_file.read()
    
    # decrypting the file
    decrypted = fernet.decrypt(encrypted)
    
    # opening the file in write mode and
    # writing the decrypted data
    with open('../public/decryption/decrypted.txt', 'wb') as dec_file:
        dec_file.write(decrypted)
        
       