# use Python 3.10+

"""Scrivere un programma in python (python3) chiamato '1-cognome.py' (tutto minuscolo)
che permetta la cifratura e decifratura di file arbitrari tramite cifrari simmetrici, usando la libreria PyCryptodome.

L'utente inizia specificando se vuole cifrare o decifrare.
L'utente deve poter specificare da input il percorso del file da cifrare/decifrare e del file dove salvare il risultato dell'operazione.

L'utente deve poi poter selezionare se vuole includere o meno l'autenticazione dei dati cifrati. Il programma deve usare cifrari ed OM adeguati alla scelta (usate 2 cifrari diversi).
In fase di cifratura la chiave va creata in maniera appropriata e poi salvata in chiaro in un file (il cui nome viene inserito dall'utente) situato nella stessa cartella del programma. Lo stesso file verrà letto in fase di decifratura (sempre chiedendo all'utente quale file usare).

Il programma deve permettere più operazioni, finché l'utente non decide di uscire.

Il programma deve gestire correttamente tutte le eccezioni che possono essere lanciate dai vari metodi, seguire pratiche crittografiche corrette, essere il più chiaro possibile (commentate a dovere).
"""

import json
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, ChaCha20
from base64 import b64encode, b64decode

# custom errors
class SymEncError(Exception):
    """Error executing Symmetric Encryption script"""
class ValidationError(SymEncError):
    """invalid input"""

# function that handles file input
# parameters:
# - name: name of the file to read
# - validate: function that validates content read,
#   should raise a ValidationError on invalid inputs
# tries to read valid content until success or user aborts
def read_file(name, validate=lambda x: None):
    try:
        # read content as bytes
        with open(name, 'rb') as in_file:
            content = in_file.read()
        try:
            # validate contents
            validate(content)
            # validation succesful, return content (end of function)
            return content
        except ValidationError as err:
            raise ValidationError('lol '+ str(err))
    except IOError as err:
        raise ValidationError(f'Error: Cannot read file {name}:\n{str(err)}')


# function that handles file output
# parameters:
# - name: name of the file to overwrite or create (if it doesn't exist)
# - data: bytes to be written in file
# tries to write data until success or user aborts
def write_file(name, data):
    try:
        # write content as bytes
        with open(name, 'wb') as out_file:
            out_file.write(data)
        return 'Data successfully written in file "' + name + '".'
    except IOError as e:
        raise ValidationError(f'Error: Cannot write file {name}: {str(e)}')

# encrypt with ChaCha20
def encrypt(path_in, path_out):
    plaintext = read_file(path_in)
    key = get_random_bytes(32)
    write_file(path_key, key)
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(plaintext)

    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ciphertext).decode('utf-8')
    result = json.dumps({'nonce': nonce, 'ciphertext': ct})
    return write_file(path_out, result)

# decrypt with ChaCha20
def decrypt(path_encrypted, path_result, key):  # files swapped
    try:
        b64 = json.loads(read_file(path_encrypted))
        nonce = b64decode(b64['nonce'])
        ciphertext = b64decode(b64['ciphertext'])
        cipher = ChaCha20.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        print("The message was " + str(plaintext)[1:])
        return write_file(path_result, str(plaintext)[1:])
    except (ValueError, KeyError):
        print("Incorrect decryption")

# function that ask the user if they wants to
# use authentication
# parameters:
# - path_in: file path to pass to encrypt/decrypt functions
# - path_out: file path to pass to encrypt/decrypt functions
    # * use AES (if auth='y') or use ChaCha20 (if auth='n')
def if_auth(path_in, path_out):
    # 'auth' can also be Unbound, 
    # I wrote 'False' to specify that it is supposed to be a boolean
    auth = False

    while True:
        auth_answer = input("\nUse authentication? (y/n)\n> ")

        match(auth_answer):
            # AES
            case 'y':
                auth = True
                # encrypt_auth()
                break
            # ChaCha20
            case 'n':
                auth = False
                encrypt(path_in, path_out)
                # decrypt(path_in, path_out)
                break
            case _:
                print(
                    "\nYou have to choose between 'y' and 'n' (yes or no)")
    return auth

def menu():
    separator = "---------------"
    print(
        f"\n{separator}\nEnter:\n  1 -> encrypt\n  2 -> decrypt\n  0 -> quit\n{separator}"
    )

    return input("> ")


# main
print("\nEncrypt and decrypt messages with AES and ChaCha20 methods!")
while True:
    choice = menu()

    try:
        # switch-case syntax in substitution to 'if elif elif elif ...'
        match choice:
            # * encrypt
            case "1":
                # ask user to enter pathname from where encrypt and where to print ciphertext
                # TODO THESE LINTERS SUCKS

                path_in = input(
                    "\nEnter the filename from where to encrypt\n> ")
                # msg = input("\nEnter message to encrypt\n> ")
                
                path_out = input(
                    "\nEnter the filename where to save the output\n> "
                )

                if_auth(path_in, path_out)

            # * decrypt
            case "2":
                if_auth(path_in, path_out)
                path_key = input('Enter the filename where the key is stored\n> ')
                key = str(read_file(path_key))
                decrypt(path_in, path_out, key)

            # * exit script
            case "0":
                exit()

            # * default case
            case _:
                print(
                    "\nTry again, please choose a number from these options: 1, 2 or 0"
                )

    except SymEncError as err:
        print(err)
