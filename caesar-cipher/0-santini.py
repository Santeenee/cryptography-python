'''
Scrivere un programma in python (python3) chiamato '0-cognome.py' che esegua la cifratura e la decifratura usando il cifrario di Cesare (shift).
Il programma deve dare all'utente la scelta tra cifrare (1), decifrare (2) o uscire (0), acquisendo la scelta da tastiera (standard input).

Se viene scelto di cifrare, il programma deve chiedere all'utente di quante lettere shiftare l'alfabeto, poi prendere in input (da tastiera) una parola o frase e cifrare questo messaggio con la chiave specificata dall'utente, infine deve stampare su schermo il risultato e salvarlo su un file chiamato 'ciphertext.txt'.

Se viene scelto di decifrare il programma deve leggere il cifrato da file, chiedere all'utente la chiave come nella cifratura, poi decifrare e stampare su schermo il cifrato letto dal file e la decifratura del messaggio.
'''

alph = 'abcdefghijklmnopqrstuvwxyz '
separator = '---------------'

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

# if n is positive, the array is shifted (rotated) to the right
def shift_alph(arr, n):
  ### print the two alphabets, before and after shifting
  print(alph)
  print(arr[n:] + arr[:n])
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
  shiftedAlph = shift_alph(alph, key_str * sign)
  # process character by character
  for index in range(len(in_str)):
    i = alph.find(in_str[index])
    # print(i)

    if i < 0:
      err_msg = '\nError: message contains invalid character: "'
      err_msg += in_str[index] + '"'
      raise CaesarCipherError(err_msg)

    # elif abs(key_str) > 26:
    #   err_msg = '\nError: key contains invalid character: "'
    #   err_msg += str(key_str) + '"'
    #   raise CaesarCipherError(err_msg)

    out_str += shiftedAlph[i]

  return out_str

# function that performs Caesar cipher encryption
def encrypt():

  # encrypt
  cipherText = enc_dec(plainText, int(shiftNum))

  # print output
  print(f'\nText encrypted.\nPlaintext: "{plainText}"\nCiphertext: "{cipherText}"')

  # write output to file
  try:
    with open('caesar-cipher/ciphertext.txt', 'w+') as out_file:
      out_file.write(cipherText)
  except IOError as err:
    raise CaesarCipherError('\nError: cannot write ciphertext in ciphertext.txt: ' + str(err))

  # note that the following message is not printed if the function
  # raised some exception previously
  print(f'\nEncrypted message correctly saved:\n"{cipherText}"')

# function that performs Caesar cipher decryption
def decrypt(key):  
  # read ciphertext from file
  cipherText = read_file('caesar-cipher/ciphertext.txt')
  print('\nThe ciphertext is:\n' + cipherText)

  # decrypt
  plainText = enc_dec(cipherText, shiftNum, -1)

  # write result on the console
  print('\nThe decrypted message is:\n' + plainText)

def menu():
  # notice the "f" before the string
  # which is used to allow variable interpolation
  print(f'\n{separator}\nPress:\n  1 -> encrypt\n  2 -> decrypt\n  0 -> quit\n{separator}')
  
  return input('> ')

#main
while True:
  choice = menu()
  shiftNum = 27

  try:
    #switch-case syntax in substitution to 'if elif elif elif ...'
    match choice:
      #* encrypt 
      case "1":
        # ask user the key, check if input is valid integer
        while abs(shiftNum) > 26:
          try:
            shiftNum = int(input('\nChoose a number between -26 and 26 to shift the alphabet\n> '))
          except ValueError:
            # better try again... Return to the start of the loop
            continue

        # read message from console
        plainText = input('\nType message to encrypt, no special characters allowed\n> ').lower()
        encrypt()
      
      #* decrypt
      case "2":
        # ask user the key, check if input is valid integer
        while abs(shiftNum) > 26:
          try:
            shiftNum = int(input('\nChoose a number between -26 and 26 to shift the alphabet\n> '))
          except ValueError:
            # better try again... Return to the start of the loop
            continue
        decrypt(shiftNum)
      case "0":
        exit()
      case _:
        print('\nTry again, enter a valid number among 1, 2 or 0')
  except CaesarCipherError as err:
    print(err)
