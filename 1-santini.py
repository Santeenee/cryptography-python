# use Python 3.10+

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
            raise ValidationError('lol ' + str(err))
    except IOError as err:
        raise ValidationError(f'Error: Cannot read file {name}:\n{str(err)}')


# function that handles file output
# parameters:
# - name: name of the file to overwrite or create (if it doesn't exist)
# - data: bytes to be written in file
def write_file(name, data):
    try:
        # write content as bytes
        with open(name, 'wb') as out_file:
            out_file.write(data)
        return 'Data successfully written in file "' + name + '".'
    except IOError as e:
        raise ValidationError(f'Error: Cannot write file {name}: {str(e)}')

# function that handles file output
# parameters:
# - name: name of the file to overwrite or create (if it doesn't exist)
# - data: string to be written in file


def write_file_txt(name, data):
    try:
        # write content as bytes
        with open(name, 'w') as out_file:
            out_file.write(data)
        return 'Data successfully written in file "' + name + '".'
    except IOError as e:
        raise ValidationError(f'Error: Cannot write file {name}: {str(e)}')

# encrypt with ChaCha20


def encrypt(path_in, path_out):

    # generate key
    path_key = input('Enter the filename where to store the key\n> ')
    key = get_random_bytes(32)
    write_file_txt(path_key, str(key))

    cipher = ChaCha20.new(key=key)

    plaintext = read_file(path_in)
    ciphertext = cipher.encrypt(plaintext)

    nonce = str(cipher.nonce)
    ct = str(ciphertext)

    result = json.dumps({'nonce': nonce, 'ciphertext': ct})
    print(f'\n\nRESULT\n{result}\n\n')
    return write_file_txt(path_out, result)

# decrypt with ChaCha20


def decrypt(path_encrypted, path_result):  # files swapped
    try:
        path_key = input(
            'Enter the filename where the key is stored\n> ')
        key = str(read_file(path_key))
        key = bytes(key[2:len(key)-1], 'utf-8')
        print(str(key))

        dataJson = json.loads(read_file(path_encrypted))
        nonce = dataJson['nonce']
        ciphertext = dataJson['ciphertext']

        print('AAAA: '+nonce)
        print('AAAA: '+nonce[2:-1])
        # print('AAAA: '+ciphertext[])

        cipher = ChaCha20.new(key=key, nonce=nonce)
        print('HEY 1')

        plaintext = cipher.decrypt(ciphertext)

        print("The message was " + str(plaintext))
        return write_file(path_result, str(plaintext))
    except (ValueError, KeyError) as err:
        print("Incorrect decryption: " + err)

# function that ask the user if they wants to
# use authentication
# parameters:
# - path_in: file path to pass to encrypt/decrypt functions
# - path_out: file path to pass to encrypt/decrypt functions
    # * use AES (if auth='y') or use ChaCha20 (if auth='n')


def if_auth(path_in, path_out, choice):
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
                if choice == "1":
                    encrypt(path_in, path_out)
                elif choice == "2":
                    decrypt(path_in, path_out)
                else:
                    print('\nHOW\n')
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

                if_auth(path_in, path_out, choice)  # contains encrypt()

            # * decrypt
            case "2":
                path_in = input(
                    "\nEnter the filename from where to decrypt\n> ")
                # msg = input("\nEnter message to encrypt\n> ")

                path_out = input(
                    "\nEnter the filename where to save the output\n> "
                )

                if_auth(path_in, path_out, choice)  # contains decrypt()

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
