import sqlite3, hashlib
import string
from tkinter import *
from tkinter import simpledialog
from functools import partial
import uuid
import pyperclip
import base64
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

backend = default_backend()
salt = b'24444'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryption_key = 0


def encrypt(key: bytes, message: bytes) -> bytes:
    return Fernet(key).encrypt(message)


def decrypt(token: bytes, message: bytes) -> bytes:
    return Fernet(token).decrypt(message)


# DATABASE

with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS MASTER_PASSWORD(
        ID INTEGER PRIMARY KEY,
        PASSWORD TEXT NOT NULL,
        RECOVERY_KEY TEXT NOT NULL
    );
""")

cursor.execute("""
    CREATE TABLE IF NOT EXISTS VAULT(
        ID INTEGER PRIMARY KEY,
        SERVICE TEXT NOT NULL,
        USERNAME TEXT NOT NULL,
        PASSWORD TEXT NOT NULL
    );
""")


# POP-UPS
def pop_up(text):
    answer = simpledialog.askstring("input string", text)

    return answer


# WINDOWS

window = Tk()

window.title("Gerenciador de senhas")


def hash_password(password):
    hashed_password = hashlib.sha256(password)
    hashed_password = hashed_password.hexdigest()

    return hashed_password


def first_visit_screen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("350x150")

    main_label = Label(window, text="Defina a senha mestre:")
    main_label.config(anchor=CENTER)
    main_label.pack()

    password_textbox = Entry(window, width=20, show="*")
    password_textbox.pack()
    password_textbox.focus()

    sub_label = Label(window, text="Digite a senha novamente")
    sub_label.config(anchor=CENTER)
    sub_label.pack()

    confirmation_textbox = Entry(window, width=20, show="*")
    confirmation_textbox.pack()
    confirmation_textbox.focus()

    error_label = Label(window)
    error_label.pack()

    def save_password():
        if password_textbox.get() == confirmation_textbox.get():
            delete_master_password = "DELETE FROM MASTER_PASSWORD WHERE ID = 1"

            cursor.execute(delete_master_password)

            hashed_password = hash_password(password_textbox.get().encode('utf-8'))
            recovery_key = hash_password(str(uuid.uuid4().hex).encode('utf-8'))

            global encryption_key
            encryption_key = base64.urlsafe_b64encode(kdf.derive(str(secrets.randbits(6)).encode()))

            insert_fields = """INSERT INTO MASTER_PASSWORD(PASSWORD, RECOVERY_KEY) VALUES (?, ?)"""
            cursor.execute(insert_fields, (hashed_password, recovery_key))
            db.commit()

            recovery_screen(recovery_key)
        else:
            error_label.config(text="As senhas não são iguais")

    button = Button(window, text="Salvar", command=save_password)
    button.pack()


def recovery_screen(recovery_key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("350x150")

    main_label = Label(window, text="Salve essa chave para poder recuperar a senha mestre")
    main_label.config(anchor=CENTER)
    main_label.pack()

    sub_label = Label(window, text=recovery_key)
    sub_label.config(anchor=CENTER)
    sub_label.pack()

    def copy_key():
        pyperclip.copy(sub_label.cget("text"))

    def close_window():
        password_vault()

    button = Button(window, text="Copiar chave", command=copy_key)
    button.pack(pady=5)

    button = Button(window, text="Fechar", command=close_window)
    button.pack(pady=5)


def reset_screen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("350x150")

    main_label = Label(window, text="Digite a chave de recuperação")
    main_label.config(anchor=CENTER)
    main_label.pack()

    main_entry = Entry(window, width=20, show="*")
    main_entry.pack()
    main_entry.focus()

    sub_label = Label(window)
    sub_label.config(anchor=CENTER)
    sub_label.pack()

    def get_recovery_key():
        recovery_check = main_entry.get()
        cursor.execute("SELECT * FROM MASTER_PASSWORD WHERE ID = 1 AND RECOVERY_KEY = ?", [recovery_check])
        return cursor.fetchall()

    def check_recovery_key():
        recovery_check = get_recovery_key()
        if recovery_check:
            first_visit_screen()
        else:
            main_entry.delete(0, 'end')
            sub_label.config(text="Chave errada")

    button = Button(window, text="Confirmar", command=check_recovery_key)
    button.pack(pady=5)


def login_screen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("350x150")

    main_label = Label(window, text="Digite a senha mestre:")
    main_label.config(anchor=CENTER)
    main_label.pack()

    password_textbox = Entry(window, width=20, show="*")
    password_textbox.pack()

    sub_label = Label(window)
    sub_label.pack()

    def get_master_password():
        password = hash_password(password_textbox.get().encode('utf-8'))

        global password_check
        password_check = password_textbox.get().encode()
        hash_check = hash_password(password_textbox.get().encode('utf-8'))

        cursor.execute("SELECT * FROM MASTER_PASSWORD WHERE ID = 1 AND PASSWORD = ?", [hash_check])
        return cursor.fetchall()

    def check_password():
        master_password = get_master_password()

        if master_password:
            password_vault()
            global encryption_key
            global password_check
            encryption_key = base64.urlsafe_b64encode(kdf.derive(password_check))
        else:
            password_textbox.delete(0, 'end')
            sub_label.config(text="Senha errada")

    def reset_password():
        reset_screen()

    save_button = Button(window, text="Confirmar", command=check_password)
    save_button.pack(pady=10)

    reset_button = Button(window, text="Recuperar senha", command=reset_password)
    reset_button.pack(pady=10)


def password_vault():
    for widget in window.winfo_children():
        widget.destroy()

    def add_entry():
        service_text = "Serviço"
        username_text = "Nome de usuário"
        password_text = "Senha"

        service = encrypt(encryption_key, pop_up(service_text).encode())
        username = encrypt(encryption_key, pop_up(username_text).encode())
        password = encrypt(encryption_key, pop_up(password_text).encode())

        insert_fields = """INSERT INTO VAULT (service, username, password) VALUES (?, ?, ?);"""
        cursor.execute(insert_fields, (service, username, password))
        db.commit()

        password_vault()

    def remove_entry(entry):
        cursor.execute("DELETE FROM VAULT WHERE id = ?", (entry,))
        db.commit()

        password_vault()

    window.geometry("740x400")

    main_label = Label(window, text="Gerenciador de senhas")
    main_label.grid(column=1)

    button = Button(window, text="Adicionar conta e senha", command=add_entry)
    button.grid(column=0, pady=10)

    random_password_button = Button(window, text="Gerar senha aleatória", command=generate_random_password)
    random_password_button.grid(column=1, row=1, pady=10)

    service_label = Label(window, text="Serviço")
    service_label.grid(row=2, column=0, padx=80)

    username_label = Label(window, text="Nome de usuário")
    username_label.grid(row=2, column=1, padx=80)

    password_label = Label(window, text="Senha")
    password_label.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM VAULT")
    if cursor.fetchall():
        i = 0
        while True:
            cursor.execute("SELECT * FROM VAULT")
            array = cursor.fetchall()

            service_label = Label(window, text=(decrypt(encryption_key, (array[i][1]))), font=("Helvetica", 12))
            service_label.grid(column=0, row=i + 3)

            username_label = Label(window, text=(decrypt(encryption_key, (array[i][2]))), font=("Helvetica", 12))
            username_label.grid(column=1, row=i + 3)

            password_label = Label(window, text=(decrypt(encryption_key, (array[i][3]))), font=("Helvetica", 12))
            password_label.grid(column=2, row=i + 3)

            button = Button(window, text="Deletar", command=partial(remove_entry, array[i][0]))
            button.grid(column=3, row=i + 3, pady=10)

            i = i + 1

            cursor.execute("SELECT * FROM VAULT")
            if len(cursor.fetchall()) <= i:
                break


def generate_random_password():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("350x150")

    alphabet = string.ascii_letters + string.digits
    while True:
        random_password = ''.join(secrets.choice(alphabet) for i in range(10))
        if (any(c.islower() for c in random_password)
                and any(c.isupper() for c in random_password)
                and sum(c.isdigit() for c in random_password) >= 3):
            break

    main_label = Label(window, text="Senha aleatória")
    main_label.config(anchor=CENTER)
    main_label.pack()

    sub_label = Label(window, text=random_password)
    sub_label.config(anchor=CENTER)
    sub_label.pack()

    def copy_key():
        pyperclip.copy(sub_label.cget("text"))

    def close_window():
        password_vault()

    button = Button(window, text="Copiar senha", command=copy_key)
    button.pack(pady=5)

    button = Button(window, text="Fechar", command=close_window)
    button.pack(pady=5)


def check_screen():
    cursor.execute("SELECT * FROM MASTER_PASSWORD")

    if cursor.fetchall():
        login_screen()
    else:
        first_visit_screen()


# MAIN

check_screen()

window.mainloop()
