'''Scrivere un programma in python (python3) chiamato '1-cognome.py' (tutto minuscolo) che permetta la cifratura e decifratura di file arbitrari tramite cifrari simmetrici, usando la libreria PyCryptodome.

L'utente inizia specificando se vuole cifrare o decifrare.
L'utente deve poter specificare da input il percorso del file da cifrare/decifrare e del file dove salvare il risultato dell'operazione.

L'utente deve poi poter selezionare se vuole includere o meno l'autenticazione dei dati cifrati. Il programma deve usare cifrari ed OM adeguati alla scelta (usate 2 cifrari diversi).
In fase di cifratura la chiave va creata in maniera appropriata e poi salvata in chiaro in un file (il cui nome viene inserito dall'utente) situato nella stessa cartella del programma. Lo stesso file verrà letto in fase di decifratura (sempre chiedendo all'utente quale file usare).

Il programma deve permettere più operazioni, finché l'utente non decide di uscire.

Il programma deve gestire correttamente tutte le eccezioni che possono essere lanciate dai vari metodi, seguire pratiche crittografiche corrette, essere il più chiaro possibile (commentate a dovere).'''

# import cryptography module
from Crypto.Random import get_random_bytes

# custom errors
class SymEncError(Exception):
    '''Error executing Symmetric Encryption script'''
class ValidationError(SymEncError):
    '''invalid input'''

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

  except SymEncError as err:
    print(err)
