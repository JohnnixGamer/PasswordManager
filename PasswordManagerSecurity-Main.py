#  La herramienta fue creada por JohnnixGamer
# Se basa en analizar la seguridad de una con
# traseña y buscar si esta filtrada en algun
# diccionario de contraseñas malicioso de
# todo internet, es muy potente, encripta
# tus contraseñas para mayor seguridad y 
# tiene una bonita interfaz grafica

import re
import time
import os
import string
import random
import requests
import hashlib
import json
import subprocess

os.system("title PasswordManager Official")

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

loading = """

           ███████████████                                   
         █████████████               d8888b.  .d8b.  .d8888. .d8888. db   d8b   db  .d88b.  d8888b. d8888b.
       ██████               ██       88  `8D d8' `8b 88'  YP 88'  YP 88   I8I   88 .8P  Y8. 88  `8D 88  `8D
      █████               ████       88oodD' 88ooo88 `8bo.   `8bo.   88   I8I   88 88    88 88oobY' 88   88
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
  ████████████████████████████████   [i] Cargando la herramienta y comprobando su conexion a internet
   ██████████████████████████████                              
   
       [i] Para su seguridad
"""

os.system("cls")
print(loading)

def get_common_passwords_list():
    url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"
    response = requests.get(url)
    return response.text.splitlines()

def sha1_hash(password):
    sha1 = hashlib.sha1()
    sha1.update(password.encode('utf-8'))
    return sha1.hexdigest().upper()

def check_password_strength(password, common_passwords):
    min_length = 8
    has_lowercase = any(char.islower() for char in password)
    has_uppercase = any(char.isupper() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special_char = any(char in '@#$%^&*()_-+={}[]|\\:;"<>,.?/~`' for char in password)
    not_common_password = password not in common_passwords

    is_strong_password = (
        len(password) >= min_length and
        has_lowercase and
        has_uppercase and
        has_digit and
        has_special_char and
        not_common_password
    )

    print("[-] Comentario de la contraseña:")
    if is_strong_password:
        print("[i] ¡Genial! Tu contraseña es segura.")
    else:
        if len(password) < min_length:
            print("[!] La contraseña es demasiado corta. Debe tener al menos 8 caracteres.")
        if not has_lowercase or not has_uppercase:
            print("[!] Incluye letras mayúsculas y minúsculas para mayor seguridad.")
        if not has_digit:
            print("[!] Incluye números para mayor seguridad.")
        if not has_special_char:
            print("[!] Incluye caracteres especiales para mayor seguridad.")
        if not not_common_password:
            print("[!] Evita usar contraseñas comunes para mayor seguridad.")

def check_password(password):
    hashed_password = hashlib.sha1(password.encode()).hexdigest().upper()
    response = requests.get(f"https://api.pwnedpasswords.com/range/{hashed_password[:5]}")
    if response.status_code == 200:
        for line in response.text.splitlines():
            leaked_hash, count = line.split(":")
            if hashed_password[5:] == leaked_hash:
                return True
    return False
    try:
        data = json.loads(response.text)
        if data["found"]:
            return True
    except json.JSONDecodeError:
        return False

    return False

def password_score(password):
    score = 0
    if len(password) >= 8:
        score += 1
    if any(char.islower() for char in password):
        score += 1
    if any(char.isupper() for char in password):
        score += 1
    if any(char.isdigit() for char in password):
        score += 1
    if any(char in '@#$%^&*()_-+={}[]|\\:;"<>,.?/~`' for char in password):
        score += 1
    return score

def encrypt_password(password):
    encrypted_password = ""
    for char in password:
        if char == "i":
            encrypted_password += "1"
        elif char == "e":
            encrypted_password += "3"
        elif char == "a":
            encrypted_password += "4"
        elif char == "s":
            encrypted_password += "5"
        elif char == "t":
            encrypted_password += "7"
        elif char == "o":
            encrypted_password += "0"
        else:
            encrypted_password += char.upper()
    return encrypted_password

def check_password_exposure(password):
    api_url = f"https://api.pwnedpasswords.com/range/{sha1_hash(password)[:5]}"
    response = requests.get(api_url)
    hashes = (line.split(':') for line in response.text.splitlines())
    found = any(sha1_hash(password)[5:] == h for h, count in hashes)
    if found:
        print("[!] ALERTA: Esta contraseña ha sido expuesta en filtraciones de datos. Elija una mas segura.")
    else:
        print("[i] ¡Buena noticia! Tu contraseña no ha sido encontrada en filtraciones de datos conocidas.")

common_passwords_list = get_common_passwords_list()

while True:
    os.system("cls")
    print(logo)
    print("[i] Menú de seguridad de contraseñas")
    print("[1] Comprobar seguridad de contraseñas")
    print("[2] Analizar ordenador en busca de vulnerabilidades en las contraseñas")
    print("[3] Salir")
    option = input("[?] Ingrese una opción: ")

    if option == "1":
        while True:
            os.system("cls")
            print(logo)
            user_password = input("[?] Ingrese una contraseña: ")
            encrypted_password = encrypt_password(user_password)
            print(f"[i] Contraseña encriptada: {encrypted_password}")
            check_password_strength(user_password, common_passwords_list)
            if check_password(user_password):
                print("[!] Hay altas probabilidades de que algun atacante malicioso tenga acceso a tus datos")
            else:
                print("[i] Hay muy bajas probabilidades de que seas hackeado")
            check_password_exposure(user_password)
            print(f"[i] Puntuación de la contraseña: {password_score(user_password)}/5")
            os.system("pause")
    
    elif option == "2":
        subprocess.run(["python", "PasswordComputer.py"])
    
    elif option == "3":
        sys.exit()
    
    else:
        print("[ERR] Opción inválida. Intente nuevamente.")
        os.system("pause")