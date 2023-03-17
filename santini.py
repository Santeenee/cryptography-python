import json
import os.path
from getpass import getpass
# Finalist (but not winner) of the NIST hash function competition,
# it is up to 3 times faster than SHA3
from Crypto.Hash import BLAKE2b
# Scrypt is a Key Derivation Function 
# meaning it derives a key from a given passfrase.
# Particularly effective against brute-force
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
# AES stands for "symmetric encryption standard"
# it is very fast and efficient compared to other
# symmetric encryption algorithms, it protects
# against side channel attacks
from Crypto.Cipher import AES

# custom errors
class SymEncError(Exception):
    '''Error executing Symmetric Encryption script'''

def getKeyByPsw(psw: str, salt):
    '''
        Generate key from a password

        Parameters:
        - psw: `string`
        - salt: if not specified or the length is incorrect it will generate a new 16 byte salt
        
        Returns:
        - generated key and the salt
    '''
    
    if len(salt) != 16:
        salt = get_random_bytes(16)
    key = scrypt(psw, salt, 16, N=2**20, r=8, p=1)
    return key, salt

def save_and_exit(path, password, credentials):
    '''
        Encrypts and saves file given the path, password and credentials

        Parameters: 
        - path: `string`
        - password: `string`
        - credentials: dict containing the credentials to save
    '''
    data = json.dumps(credentials, ensure_ascii=False).encode('utf-8')
    
    salt = get_random_bytes(16)
    key = scrypt(password, salt, 16, N=2**20, r=8, p=1)
    # AES is used (standard) for symmetric encryption
    cipher = AES.new(key, AES.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    with open(path, 'wb') as out_file:
        out_file.write(salt)
        out_file.write(cipher.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)

def search_and_add(query, dic):
    '''
        Searchs for credentials
        If there is no credentials then they are added

        Parameters:
        - query: `string`
        - dic: `string`

        Returns:
        - dic
    '''
    if query in dic:
        print('username: ', dic[query]['username'])
        print('password: ', dic[query]['password'])
    else:
        prompt = 'Credentials not found. Add new entry?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        add = input(prompt)
        if add == 'y':
            username_n = input('Insert username: ')
            password_n = getpass('Insert password: ')
            dic[query] = {
                    'username': username_n,
                    'password': password_n
                    }
    return dic

def load_data(path, password):
    '''
        Decrypts given file

        Parameters:
        - path: `string`
        - password: `string` used to derive key

        Returns:
        - credentials in file
    '''
    with open(path, 'rb') as in_file:
        key = scrypt(password, in_file.read(16), 16, N=2**20, r=8, p=1)
        nonce = in_file.read(15)
        tag = in_file.read(16)
        ciphertext = in_file.read(-1)
            
    cipher = AES.new(key, AES.MODE_OCB, nonce)
    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise SymEncError('Decryption error: authentication failure')
    

    try: 
        credentials = json.loads(data.decode('utf-8'))
    except ValueError as err:
        raise IOError(f'data not valid: {str(err)}')
    return credentials

def log_in(username, password):
    '''
        Log in flow
        Uses Blake2b hashing function, it allows up to 64bits

        Parameters:
        - username: `string`
        - password: `string`
    '''
    blake_hash = BLAKE2b.new(data = username.encode('utf-8'), digest_bytes=64)
    path_file = blake_hash.hexdigest()
    
    if os.path.exists(path_file):        
        try:
            credentials = load_data(path_file, password)
        except ValueError as err:
            print('Autentication failed')
            return
        except IOError as err:
            print('Error loading data:')
            print(err)
            return
        
    else:
        prompt = 'User not found. Add as new?'
        prompt += '\n(y to continue, anything else to cancel)\n'
        sign_up = input(prompt)
        if sign_up == 'y':
            credentials = {}
        else:
            return
    
    prompt = 'Credentials to search:'
    prompt += '\n(leave blank and press "enter" to save and exit)\n'
    while True:
        query = input(prompt)
        if query != '':
            credentials = search_and_add(query, credentials)
        else:
            try:
                print('Saving data...')
                save_and_exit(path_file, password, credentials)
                print('Data saved!')
            except IOError:
                print('Error while saving, new data has not been updated!')
            return

#* MAIN
while True:
    print('Insert username and password to load data,')
    print('leave blank and press "enter" to exit.')
    username = input('Username: ')
    if username == '':
        print('Goodbye!')
        exit()
    else:
        # read password
        password = getpass()
        log_in(username, password)
