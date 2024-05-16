# Написать программу на Python, которая проверяет вводимый поьзователем пароль на сложность:
# не менее 8 символов
# наличие прописных и строчных букв
# наличие цифр
# и переводит его в хэш-значение.

import hashlib

flag = 1

def ui():
    while flag:
        password_to_check = input('Enter a password you wish to check:\n')
        check_password(password_to_check)
    hash_password(password_to_check)

def check_password(password):
    global flag
    if len(password) < 8:
        print('Password is too short')
    elif not any(char.isupper() for char in password):
        print('Password must contain at least one uppercase letter')
    elif not any(char.islower() for char in password):
        print('Password must contain at least one lowercase letter')
    elif not any(char.isdigit() for char in password):
        print('Password must contain at least one number')
    else:
        print('Password is strong')
        flag = 0

def hash_password(password):
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    print(hashed_password)

ui()

