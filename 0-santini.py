alph = 'abcdefghijklmnopqrstuvwxyz '

#custom error
class CaesarCipherError(Exception):
  '''Error executing Caesar cipher script'''

def read_file(name):
  try:
    # open in read mode a text file
    with open(name, 'r') as in_file:
      out_str = in_file.read()
  except IOError as err:
    raise CaesarCipherError('Error: Cannot read ' + name + ' file: ' + str(err))
  # delete possible trailing newlines
  return out_str.strip('\n')

# if n is positive, the array is shited (rotated) to the right
def shift_alph(arr, n):
  # arr[n:] takes the characters from the index 'n' onwards
  # arr[:n] takes the characters before the index 'n'
  return arr[n:] + arr[:n]

def enc_dec(in_str, key_str, sign = 1):
  # check sign
  if (abs(sign) != 1):
    err_msg = 'Error: sign parameter should be either 1 or -1, got: '
    err_msg += sign
    raise CaesarCipherError(err_msg)
    # note that this error does not depend on user's input
    # so it should not be raised if the script is correct

  ### compute resulting string
  out_str = ''
  shifted_alph = shift_alph(alph, key_str * sign)

  # process character by character
  for charIndex in range(len(in_str)):
    # search for the 'in_str' character by character position in 'alph'
    i = alph.find(in_str[charIndex])

    if i < 0:
      err_msg = '\nError: message contains invalid character: "'
      err_msg += in_str[charIndex] + '"'
      raise CaesarCipherError(err_msg)

    # put that position 'i' in 'shifted_alph'. 
    # every loop cycle append the corresponding character to 'out_str'
    out_str += shifted_alph[i]

  return out_str

# function that performs Caesar cipher encryption
def encrypt(plain_text, shift_num):

  # encrypt
  cipher_text = enc_dec(plain_text, shift_num)

  # write output to file
  try:
    with open('./ciphertext.txt', 'w+') as out_file:
      out_file.write(cipher_text)
  except IOError as err:
    raise CaesarCipherError('\nError: cannot write ciphertext in ciphertext.txt: ' + str(err))

  # note that the following message is not printed if the function
  # raised some exception previously
  print(f'\nEncrypted message correctly saved:\n"{cipher_text}"')

# function that performs Caesar cipher decryption
def decrypt(shift_num):  
  # read ciphertext from file
  cipher_text = read_file('./ciphertext.txt')
  print('\nThe ciphertext is:\n' + cipher_text)

  # decrypt
  plain_text = enc_dec(cipher_text, shift_num, -1)

  # write result on the console
  print('\nThe decrypted message is:\n' + plain_text)

def menu():
  separator = '---------------'

  # notice the "f" before the string
  # which is used to allow for variable interpolation
  print(f'\n{separator}\nEnter:\n  1 -> encrypt\n  2 -> decrypt\n  0 -> quit\n{separator}')
  
  return input('> ')

#main
print('\nEncrypt and decrypt messages with the Caesar cipher method!')
while True:
  choice = menu()
  shift_num = 27

  try:
    #switch-case syntax in substitution to 'if elif elif elif ...'
    match choice:
      #* encrypt 
      case "1":
        # ask user the key, check if input is valid integer
        while abs(shift_num) > 26:
          try:
            shift_num = int(input('\nChoose a number between -26 and 26 to shift the alphabet\n> '))
          except ValueError:
            print('\nError: value entered is not a number, try again.')
            # better try again... Return to the start of the loop
            continue
          if abs(shift_num) > 26:
            print('\nError: expected value must be between -26 and 26')

        # read message from console
        plain_text = input('\nType message to encrypt, no special characters allowed\n> ').lower()
        
        encrypt(plain_text, shift_num)
      
      #* decrypt
      case "2":
        # ask user the key, check if input is valid integer
        while abs(shift_num) > 26:
          try:
            shift_num = int(input('\nChoose a number between -26 and 26 to shift the alphabet\n> '))
          except ValueError:
            print('\nError: value entered is invalid, try again.')
            # better try again... Return to the start of the loop
            continue
          if abs(shift_num) > 26:
            print('\nError: value entered must be between -26 and 26')
        
        decrypt(shift_num)
      
      #* exit script
      case "0":
        exit()
      
      #* default case
      case _:
        print('\nTry again, please choose a number from these options: 1, 2 or 0')

  except CaesarCipherError as err:
    print(err)
