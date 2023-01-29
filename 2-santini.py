# --Symmetric Encryption--

# import cryptography modules
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from getpass import getpass
from Crypto.Protocol.KDF import scrypt

# custom errors
class SymEncError(Exception):
    '''Error executing Symmetric Encryption script'''
class ValidationError(SymEncError):
    '''invalid input'''

# function that handles file input
# parameters:
# - prompt: message to display acquiring file path
# - validate: function that validates content read,
#   should raise a ValidationError on invalid inputs
# tries to read valid content until success or user aborts
def read_file(prompt, validate = lambda x : None):
    # repeat until a validated input is read or user aborts
    while True:
        # acquire file path
        path = input(prompt)
        # read input managing IOErrors
        try:
            # read content as bytes
            with open(path, 'rb') as in_file:
                content = in_file.read()
            try:
                # validate contents
                validate(content)
                # validation successful, return content (end of function)
                return content
            except ValidationError as err:
                # print validation error
                print(err)
        except IOError as err:
            print('Error: Cannot read file ' + path + ': ' + str(err))
        # no valid content read: try again or abort
        choice = input('(q to abort, anything else to try again) ')
        if choice == 'q':
            raise SymEncError('Input aborted')

# function that handles file output
# parameters:
# - prompt: message to display acquiring file path
# - data: bytes to be written in file
# tries to write data until success or user aborts
def write_file(prompt, data):
    # repeat until  write or user aborts
    while True:
        # acquire file path
        path = input(prompt)
        # write input managing IOErrors
        try:
            # write content as bytes
            with open(path, 'wb') as out_file:
                out_file.write(data)
            return 'Data ly written in file "' + path + '".'
        except IOError as e:
            print('Error: Cannot write file ' + path + ': ' + str(e))
        # write unsuccessful: try again or abort
        choice = input('(q to abort, anything else to try again) ')
        if choice == 'q':
            raise SymEncError('Output aborted')

# function that generates prompts for reading and writing files
# parameters:
# - f_type: string that describes the file
# - read: boolean that tells if the prompt is for input or not
def gen_prompt(f_type, reading):
    message = "\nPlease insert path of the file "
    if reading:
        message += "that contains the " + f_type
    else:
        message += "where to save the " + f_type
    return message + ": "


# function that generates key from user password and salt
def  get_key_salt (is_encrypt:bool, salt:bytes = b''):
    password = getpass("\nInsert password to generate key: ")

    if is_encrypt:
        salt = get_random_bytes(16)

    # A good choice of parameters (N, r , p) was suggested by Colin Percival
    # in his presentation in 2009:
    # http://www.tarsnap.com/scrypt/scrypt-slides.pdf
    #
    # ( 2²⁰, 8, 1 ) for file encryption (≤5s)
    key = scrypt(password, salt, 16, N=2**20, r=8, p=1)
    
    if is_encrypt:
        return key, salt

    return key

# function that performs encryption with authentication
#* uses KDF 'Scrypt' to derive a key from a password and salt
def encrypt():
    # read file to encrypt, no validation
    p_data = read_file(gen_prompt("data to encrypt", True))

    # generate key using the Key Derivation Function 'scrypt'
    key, salt =  get_key_salt (True)

    cipher = AES.new(key, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(p_data)
    c_data = cipher.nonce + tag + salt + ciphertext
    
    # output
    print(write_file(gen_prompt("encrypted data", False), c_data))

# function that validates key length
# parameters:
# data: byte string to check
# k_len: length in bytes the key must have
def check_k_len(data, k_len):
    if len(data) != k_len:
        err_msg = 'Error: the key must be exactly '
        err_msg += k_len + ' bytes long, the input was '
        err_msg += len(data) + ' bytes long.'
        raise ValidationError(err_msg)

# function that validates ciphertext file length
# parameters:
# data: byte string to check
# c_len: length in bytes the key must have
def check_c_len(data, c_len):
    if len(data) < c_len:
        err_msg = 'Error: the ciphertext must be at least '
        err_msg += c_len + ' bytes long, the input was '
        err_msg += len(data) + ' bytes long.'
        raise ValidationError(err_msg)

# function that performs decryption
# parameters:
# auth: boolean that tells whether to perform authentication


def decrypt():
    # read ciphertext validating its length
    c_data = read_file(
        gen_prompt("data to decrypt", True),
        lambda data: check_c_len(data, 31)
    )

    # decryption
    nonce = c_data[:15]
    tag = c_data[15:31]
    salt = c_data[31:47]
    ciphertext = c_data[47:]

    # use salt in  get_key_salt  function
    key =  get_key_salt (False, salt)

    cipher = AES.new(key, AES.MODE_OCB, nonce)

    try:
        p_data = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise SymEncError('Decryption error: authentication failure')

    # output
    print(write_file(gen_prompt("decrypted data", False), p_data))

def menu():
    separator = "---------------"
    print(
        f"\n{separator}\nEnter:\n  1 -> encrypt\n  2 -> decrypt\n  0 -> quit\n{separator}"
    )

    return input("> ")

# * main
while True:
    # get user's choice and call appropriate function
    # errors are captured and printed out
    # authentication is needed
    choice = menu()
    try:
        if choice == '1':
            encrypt()
        elif choice == '2':
            decrypt()
        elif choice == '0':
            exit()
        else:
            # default error message for wrong inputs
            print('Invalid choice, please try again!')
    except SymEncError as e:
        print(e)