'''
GOAL:

Scrivere un programma in python (python3) chiamato '1-cognome.py' (tutto minuscolo) che permetta la cifratura
e decifratura di file arbitrari tramite cifrari simmetrici, usando la libreria PyCryptodome.
L'utente inizia specificando se vuole cifrare o decifrare.
L'utente deve poter specificare da input il percorso del file da cifrare/decifrare e del file dove salvare il risultato dell'operazione.
L'utente deve poi poter selezionare se vuole includere o meno l'autenticazione dei dati cifrati.
Il programma deve usare cifrari ed OM adeguati alla scelta (usate 2 cifrari diversi).
In fase di cifratura la chiave va creata in maniera appropriata e poi salvata in chiaro in un file 
(il cui nome viene inserito dall'utente) situato nella stessa cartella del programma.
Lo stesso file verrà letto in fase di decifratura (sempre chiedendo all'utente quale file usare).
Il programma deve permettere più operazioni, finché l'utente non decide di uscire.
Il programma deve gestire correttamente tutte le eccezioni che possono essere lanciate dai vari metodi,
seguire pratiche crittografiche corrette, essere il più chiaro possibile (commentate a dovere).

Author: Alex Iachemet

# # WARNINIG # # 
It works only with authentication, but I haven't got errors. I cannot understand why.
'''

# import library
import json
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, ChaCha20
from base64 import b64encode, b64decode


# custom errors
class SymEncError(Exception):
    '''Error executing Symmetric Encryption script'''
class ValidationError(SymEncError):
    '''invalid input'''

# reading a file by the path
def read_file(name):
    try:
        with open(name, 'rb') as in_file:        
            out_str = in_file.read()
    except IOError as e:
        raise ValidationError('Error: Cannot read ' + name + ' file: ' + str(e))
    return out_str
# -- -- --

# write bytes on a file
def write_file(name, msg, path = ''):
    try:
        if path == '':
            with open(path + name, "wb") as binary_file:
                # Write bytes to file
                binary_file.write(msg)
        else:
            with open(path + '\\' + name, "wb") as binary_file:
                # Write bytes to file
                binary_file.write(msg)

    except IOError as e:
        raise ValidationError('Error: Cannot read ' + name + ' file: ' + str(e))
# -- -- --

'''
This func encrypts a file without authentication
msg: file already converted in bytes
Raise ValueError if the message is not correct
More info on: https://pycryptodome.readthedocs.io/en/latest/src/cipher/chacha20.html
'''
def encrypt(msg = None, key_file_name = 'key_file'):
    if msg == None:
        raise ValueError('Wrong message for encryption!')
    
    # key generation 32 bytes
    key = get_random_bytes(32)
    
    # write the key on a file
    try:        
        write_file(key_file_name, key)
    except ValidationError as e:
        raise ValidationError(e)

    # new chacha20 cipher (buffer=bytes)
    chacha_cipher = ChaCha20.new(key=key)

    encrypted_bytes = chacha_cipher.encrypt(msg)    

    # encoding nonce and the crypted message
    nonce = b64encode(chacha_cipher.nonce)#.decode('utf-8')
    enc_byt = b64encode(encrypted_bytes)#.decode('utf-8')

    # This method allows you to convert a python object into a serialized JSON object
    try: 
        final_msg = [enc_byt, nonce]        
    except TypeError as e:
        print(str(e))

    return final_msg
# -- -- --

'''
This func decrypts a file without authentication
msg_dec: file in bytes
key: file with key in bytes
nonce: file with nonce in bytes
return the decrypted bytes
'''
def decrypt(msg_dec, key, nonce):
    decipher = 0
    try:
        decipher = ChaCha20.new(key=key, nonce=nonce)
    except (ValueError, KeyError) as e:
        print("Incorrect decryption" + str(e))
    
    return decipher.decrypt(msg_dec)
# -- -- --

'''
This func encrypts with AES EAX mode
msg: file in bytes
key_file_name: name and path of where the key is going to be saved
return an array that contains the message, the nonce and the tag
'''
def encryptAuth(msg, key_file_name):
    key = get_random_bytes(16)

    # write the key on a file
    try:        
        if key_file_name == '':
            write_file('key_file_auth', key)
        else:
            write_file(key_file_name, key)

    except ValidationError as e:
        raise ValidationError(e)

    aes_cipher = AES.new(key, AES.MODE_EAX)

    nonce = aes_cipher.nonce

    result, tag = aes_cipher.encrypt_and_digest(msg)

    return [result, nonce, tag]
# -- -- --

'''
This func decrypts a file ciphred with AES EAX mode
msg: File in bytes
key: file with the key in bytes
nonce: file with the nonce in bytes
tag: file with the tag in bytes
return the message if it is authenticated else it will raise a ValidationException
'''
def decryptAuth(msg, key, nonce, tag):
    decipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    result = decipher.decrypt(msg)

    try:
        decipher.verify(tag)
    except ValueError as e:
        raise ValidationError(str(e))
    
    return result
# -- -- --


### MAIN ###
while True:
    user = input('1: Encrypt a file\n2: Decrypt a file\n0: Quit\n')    

    try:
        if user == '0':
            print('Thankyou for using my software!')
            quit()

        if user == '1':
            path_input_enc = input('Insert the path of the file that has to be encrypted:')
            path_output_enc = input('Insert the destination of the new file encrypted: ')
            auth = input('Would you like authentication enable? (y/n) ')            
            key_file_name = input('Write the name of the file where the key is going to be saved: (default: key_file) ')

            msg_enc = read_file(path_input_enc)            

            ### Encryption ###

            if auth == 'y':
                # With authentication
                try:
                    arr_enc = encryptAuth(msg_enc, key_file_name)
                except ValidationError as e:
                    raise SymEncError(str(e))

                write_file('msg_encrypted_auth', arr_enc[0], path_output_enc)
                write_file('nonce_auth', arr_enc[1], path_output_enc)
                write_file('tag', arr_enc[2], path_output_enc)

            elif auth == 'n':
                
                # Without authentication                                                

                try:
                    if key_file_name == '':
                        final_msg_arr = encrypt(msg_enc)
                    else:
                        final_msg_arr = encrypt(msg_enc, key_file_name)                                                            
                    
                    write_file('msg_encrypted', final_msg_arr[0], path_output_enc)
                    write_file('nonce', final_msg_arr[1], path_output_enc)                    

                    
                except ValidationError as e:
                    raise SymEncError('Error: ' + str(e))                                

            else:
                print('Invalid data!')

        elif user == '2':
            ### Decryption ###

            path_input_dec = input('Insert the path of the file that has to be decrypted: ')
            msg_dec = read_file(path_input_dec)

            path_output_dec = input('Insert the destination of the new file decrypted: ')

            path_nonce_input = input('Insert the path of the "nonce" file (usually near the encrypted one): ')
            nonce_dec = read_file(path_nonce_input)

            auth = input('Would you like authentication enable? (y/n)')

            key_file_path = input('Insert the path and the name of the file that contains the key: ')
            key_dec = read_file(key_file_path)                        

            if auth == 'y':
                # With authentication
                tag_dec = read_file(input('Insert the path of the file with the tag: '))
                final_msg_dec_auth = decryptAuth(msg_dec, key_dec, nonce_dec, tag_dec)

                print(final_msg_dec_auth)
            elif auth == 'n':
                
                # Without authentication
            
                try:                    
                    final_msg_dec = decrypt(msg_dec, key_dec, nonce_dec)

                    write_file('msg_decrypted', final_msg_dec, path_output_dec)
                    print(final_msg_dec)
                
                except ValidationError as e:
                    raise SymEncError('Error: ' + str(e)) 
                        
        else:
            print('Invalid Data')
    except IOError as e:
        print(e)        