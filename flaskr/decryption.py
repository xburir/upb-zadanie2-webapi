# import required module
import sys
from Crypto.Cipher import AES
import rsa


def decrypt_RSA(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False

def decrypt_file(file_filename, RSA_key):
    # opening the encrypted file
    print("opening "+'../public/decryption/'+file_filename)
    with open('../public/decryption/'+file_filename, 'rb') as enc_file:
        enc_bytes_load = enc_file.read()
    
    enc_bytes=enc_bytes_load.split(b',,')
    
    tag = enc_bytes[0]

    nonce = enc_bytes[1]

    aes_encrypted = enc_bytes[2]

    ciphertext = enc_bytes[3]
    
    aes_decrypted = decrypt_RSA(aes_encrypted, RSA_key)

    print('\n--> decryption\ntag: ', tag, '\nnonce: ', nonce, '\nencrypted text: ', ciphertext,
         '\nAES_key: ', aes_decrypted, '\nAES_encrypted: ', aes_encrypted , '\n Split text:', enc_bytes, '\n<--\n',
           file=sys.stderr)
        
    print("Length of bytes of AES_KEY_ENCRYPTED: ", len(aes_encrypted), file=sys.stderr)
    print("Length of bytes of AES_KEY: ", len(aes_decrypted), file=sys.stderr)
    print("AES_DECRYPTED DATA TYPE: ", type(aes_decrypted), file=sys.stderr)

    # decrypting the file
    cipher = AES.new(aes_decrypted.encode("utf8") , AES.MODE_EAX, nonce=nonce)
    decrypted = cipher.decrypt(ciphertext)

    # check integrity
    try:
        cipher.verify(tag)
        print("Integrity check: The file is authentic:", decrypted)
    except ValueError:
        print("Integrity check: Key incorrect or file corrupted")

    # opening the file in write mode and
    # writing the decrypted data
    with open('../public/decryption/decrypted.txt', 'wb') as dec_file:
         dec_file.write(decrypted)

    
       