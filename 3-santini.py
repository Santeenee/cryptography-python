from Crypto.PublicKey import RSA
from getpass import getpass
from genericpath import isfile
from Crypto.Cipher import PKCS1_OAEP

class HybEncError(Exception):
    '''Error executing Hybrid Encryption script'''

class ReadProcessingError(HybEncError):
    '''Error preprocessing data read from file'''

class InvalidKey(HybEncError):
    '''Invalid input key'''


# funtion that reads files
# parameters:
# - subject: what the file should contain
# - error: error message to show when aborting
# - default: name of file to open if not specified
# - process: function to call on data,
#       reading is not considered complete unless
#       this function is called successfully.
#       Should raise ReadProcessingError on errors
# returns data read (and processed) and name of file read
def read_file(subject, error, default='', process=lambda data: data):
    #prepare string to print, including default choice
    prompt = '\nInsert path to ' + subject + ' file'
    if default != '':
        prompt += ' (' + default + ')' 
    prompt += '\n> '
    #try until file is correctly read or user aborts
    while True:
        #read choice, use default if empty
        in_filename = input(prompt)
        if in_filename  == '':
            in_filename  = default
        #read and process data
        try:
            with open(in_filename, 'rb') as in_file:
                data = in_file.read()
            return process(data), in_filename
        except (IOError, ReadProcessingError) as e:
            print('\nError while reading '+subject+':\n'+str(e))
            #let user abort reading file
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                #abort
                raise HybEncError(error)

# function to write on file
# parameters:
# - data: what to write to file
# - subject: description of what the file will contain
# - error: error message to show when aborting
# - default: name of file to open if not specified
# returns name of file written
def write_file(data, subject, error, default=''):    
    #try until file is correctly written or user aborts
    while True:
        # prepare string to print, including default choice
        prompt = '\nInsert path to file where to save ' + subject
        if default != '':
            prompt += ' (' + default + ')' 
        prompt += '\n> '
        # read choice, use default if empty
        out_filename = input(prompt)
        if out_filename  == '':
            out_filename  = default
        try:
            # warn before overwriting
            if isfile(out_filename):
                prompt = '\nFile exists, overwrite? '
                prompt += '(n to cancel, anything else to continue)\n'
                overwrite = input(prompt)
                if overwrite.lower() == 'n':
                    continue
            # write data
            with open(out_filename, 'wb') as out_file:
                out_file.write(data)
            return out_filename
        except IOError as e:
            print('\nError while saving '+subject+': '+str(e))
            # let user abort writing file
            c = input('q to quit, anything else to try again: ')
            if c.lower() == 'q':
                # abort
                raise HybEncError(error)

# function that validates ciphertext file length
# parameters:
# data: byte string to check
# c_len: length in bytes the key must have
def check_c_len(data, c_len):
    if len(data) >= c_len:
        return data
    else:
        message = 'Error: the ciphertext must be at least '
        message += str(c_len) + ' bytes long.'
        raise ReadProcessingError(message)

# function that acquires a non-empty passphrase
# for private key protection
def get_passphrase():
    prompt = "\nInsert password for the private key: "
    while True:
        pw = getpass(prompt)
        if pw != '':
            return pw
        else:
            prompt = "please enter a non-empty password: "

# function that generates the private key  
# Parameters:
# - length: integer
def generate_key(length = 2048):    
    # The FIPS standard only defines 1024, 2048 and 3072 bit key lengths
    if length in {1024, 2048, 3072}:
        key = RSA.generate(length)        
        
    else:
        raise InvalidKey('The number must be 1024, 2048 or 3072.')
    
    psw = get_passphrase()
    private_key = key.export_key('PEM', psw, 8, 'scryptAndAES128-CBC')
    public_key = key.public_key().export_key('PEM')
    save_key(private_key, True)
    save_key(public_key, False)

# function that saves the keys on a file
# key: public or private
# is_private: boolean (true if private, false if public)
# return: string, path of the file where the key is stored
def save_key(key, is_private: bool):    
    if is_private:
        settings = {
            'data': key,
            'subject': 'encrypted private key', 
            'error':'Saving encrypted private key aborted.', 
            'default':'private.pem'
        }
        
    else:
        settings = {
            'data': key,
            'subject': 'public key', 
            'error':'Saving public key aborted.', 
            'default':'public.pem'
        }
    
    #return path of the file where the key is stored
    return write_file(**settings)

# function that encrypts a message with PKCS1_OAEP
def encrypt():
    msg, _ = read_file(
        'message to encrypt', 
        'Reading message file aborted',
        'msg.txt'
    )

    pub_key, _ = read_file(
        'Public key',
        'Reading public key file aborted',
        'public.pem'
    )
    
    try:
        pub_key_imp = RSA.import_key(pub_key)
    except(ValueError, IndexError, TypeError) as e:
        raise InvalidKey('Invalid key: ' + str(e))

    cipher = PKCS1_OAEP.new(pub_key_imp)

    try:
        ciphertext = cipher.encrypt(msg)
    except (ValueError, TypeError) as e:
        raise InvalidKey('Invalid key: ' + str(e))

    write_file(
        ciphertext,
        'ciphertext',
        'Writing ciphertext aborted',
        'msg-enc.txt'
    )

# function that decrypts the ciphertext saving it on a file
def decrypt():
    enc_msg, _ = read_file(
        'encrypted',
        'Reading enc_file aborted',
        'msg-enc.txt'
    )

    private_key_enc, _ = read_file(
        'private key',
        'Reading private key file aborted',
        'private.pem',
        lambda data: check_c_len(data, 256)
    )
    
    try:
        private_key = RSA.import_key(private_key_enc, get_passphrase())
    except(ValueError, IndexError, TypeError) as e:
        raise InvalidKey('Invalid key: ' + str(e))
        
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(enc_msg)
    write_file(
        plaintext,
        'decrypted message',
        'Decryption aborted',
        'msg-dec.txt'
    )


#* ----
#* MAIN
#* ----
menu_text = '''
---------------
Enter:
  1 -> RSA key generation
  2 -> encrypt with PKCS1_OAEP
  3 -> decrypt
  0 -> quit
---------------
> '''

print('\nThis is a script that uses hybrid encryption with RSA and PKCS1_OAEP')
while True:
    # get user's choice and call appropriate function
    # errors are captured and printed out
    choice = input(menu_text)
    try:
        if choice == '1':
            generate_key()

        elif choice == '2':
            encrypt()

        elif choice == '3':
            decrypt()

        elif choice == '0':
            exit()

        else:
            # default error message for wrong inputs
            print('\nInvalid choice, please try again!')
    except HybEncError as e:
        print(e)
