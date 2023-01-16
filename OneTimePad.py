#alphabet, including space
alph = 'abcdefghijklmnopqrstuvwxyz '
#custom error
class OTPError(Exception):
  '''Error executing OTP script'''

#function that performs the core operation of OTP encryption and decryption
# parameters:
# - in_str: the string to be encrypted/decrypted
# - key_str: the string to be used as key
# - sign: an integer that specifies whether to
#       encrypt (if it has value 1)
#       decrypt (if it has value -1)
#     note that the two operations may be swapped, it only matters
#     that the signs are opposite
# returns the processed string
def enc_dec(in_str, key_str, sign):
  ### check inputs
  # check string lengths
  n = len(in_str)
  if (n > len(key_str)):
    print('Warning: message too long, will be truncated.')
    n = len(key_str)
  # check sign
  if (abs(sign) != 1):
    err_msg = 'Error: sign parameter should be either 1 or -1, got: '
    err_msg += sign
    raise OTPError(err_msg)
    # note that this error does not depend on user's input
    # so it should not be raised if the script is correct

  ### compute resulting string
  out_str = ''
  # process character by character
  for index in range(n):
    i = alph.find(in_str[index])
    j = alph.find(key_str[index])
    if i < 0:
      err_msg = 'Error: message contains invalid character: "'
      err_msg += in_str[index] + '"'
      raise OTPError(err_msg)
    elif j < 0:
      err_msg = 'Error: key contains invalid character: "'
      err_msg += key_str[index] + '"'
      raise OTPError(err_msg)
    # core operation: addition/subtraction
    # modulo the lenght of the alphabet
    out_str += alph[(i + j * sign) % len(alph)]
  return out_str

# read a text file following best practices
# parameters:
# - name: complete filename (including extensions)
#     note that it should contain also the (relative) path
#     if it is not located in the same folder as the one
#     from which the script has been launched
#     (usually the script's folder)
# returns the text contained in the file, without trailing newlines
def read_file(name):
  try:
    # open in read mode a text file
    with open(name, 'r') as in_file:
      out_str = in_file.read()
  except IOError as e:
    raise OTPError('Error: Cannot read ' + name + ' file: ' + str(e))
  # delete possible trailing newlines
  return out_str.strip('\n')

# function that performs OTP encryption
def encrypt():
  # read key from file
  key = read_file('key.txt')
  # read message from console
  pt = input('Type message to encrypt:\n')
  # encrypt
  ct = enc_dec(pt, key, 1)
  # write output
  try:
    with open('ciphertext.txt', 'w') as out_file:
      out_file.write(ct)
  except IOError as e:
    raise OTPError('Error: cannot write ciphertext: ' + str(e))
  # note that the following message is not printed if the function 
  # raised some exception previously
  print('Encrypted message correctly saved:\n' + ct)

# function that performs OTP decryption
def decrypt():
  # read key from file
  key = read_file('key.txt')
  # read ciphertext from file
  ct = read_file('ciphertext.txt')
  print('The ciphertext is:\n' + ct)
  # decrypt
  pt = enc_dec(ct, key, -1)
  # write result on the console
  print('The decrypted message is:\n' + pt)

# main
while True:
  prompt = '''What do you want to do?
  1 -> encrypt
  2 -> decrypt
  0 -> quit
-> '''
  # get user's choice and call the appropriate function
  # errors are captured and printed out
  choice = input(prompt)
  try:
    if choice == '1':
      encrypt()
    elif choice == '2':
      decrypt()
    elif choice == '0':
      exit()
    else:
      print('Invalid choice, please try again!')
  except OTPError as e:
    print(e)