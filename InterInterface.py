import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode



def generate_key():
    return os.urandom(32)


def encrypt_file(key, input_file, output_file):
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)

def decrypt_file(key, input_file, output_file):
    with open(input_file, 'rb') as f:
        file_data = f.read()

    iv = file_data[:16]
    ciphertext = file_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()


    with open(output_file, 'wb') as f:
        f.write(plaintext)

class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Шифровальщик файлов AES-256")
        self.root.geometry("500x300")

        self.create_widgets()

    def create_widgets(self):
        # Выбор действия
        ttk.Label(self.root, text="Действие:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.action_var = tk.StringVar(value="encrypt")
        ttk.Radiobutton(self.root, text="Зашифровать", variable=self.action_var, value="encrypt").grid(row=0, column=1, padx=10, pady=10)
        ttk.Radiobutton(self.root, text="Расшифровать", variable=self.action_var, value="decrypt").grid(row=0, column=2, padx=10, pady=10)

        # Поле для выбора входного файла
        ttk.Label(self.root, text="Входной файл:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.input_entry = ttk.Entry(self.root, width=40)
        self.input_entry.grid(row=1, column=1, padx=10, pady=10, columnspan=2)
        ttk.Button(self.root, text="Обзор", command=self.browse_input).grid(row=1, column=3, padx=10, pady=10)


        # Поле для выбора выходного файла
        ttk.Label(self.root, text="Выходной файл:").grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.output_entry = ttk.Entry(self.root, width=40)
        self.output_entry.grid(row=2, column=1, padx=10, pady=10, columnspan=2)
        ttk.Button(self.root, text="Обзор", command=self.browse_output).grid(row=2, column=3, padx=10, pady=10)

        # Поле для ключа
        ttk.Label(self.root, text="Ключ (Base64):").grid(row=3, column=0, padx=10, pady=10, sticky="w")
        self.key_entry = ttk.Entry(self.root, width=40)
        self.key_entry.grid(row=3, column=1, padx=10, pady=10, columnspan=2)
        ttk.Button(self.root, text="Сгенерировать", command=self.generate_key).grid(row=3, column=3, padx=10, pady=10)

        # Кнопка запуска операции
        ttk.Button(self.root, text="Выполнить", command=self.execute_operation).grid(row=4, column=1, columnspan=2, pady=20)

        # Статусная строка
        self.status_label = ttk.Label(self.root, text="Готов к работе", foreground="blue")
        self.status_label.grid(row=5, column=0, columnspan=4, pady=10)

    def browse_input(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, filename)

    def browse_output(self):
        filename = filedialog.asksaveasfilename()
        if filename:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, filename)

    def generate_key(self):
        key = generate_key()
        base64_key = urlsafe_b64encode(key).decode()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, base64_key)
        messagebox.showinfo("Ключ сгенерирован", "Ключ сгенерирован и помещён в поле. Сохраните его для расшифровки!")

    def execute_operation(self):
        action = self.action_var.get()
        input_file = self.input_entry.get()
        output_file = self.output_entry.get()
        key_str = self.key_entry.get()

        if not input_file or not output_file:
            messagebox.showerror("Ошибка", "Укажите входной и выходной файлы!")
            return

        try:
            if key_str:
                key = urlsafe_b64decode(key_str)
                if len(key) != 32:
                    messagebox.showerror("Ошибка", "Ключ должен быть 32 байта (256 бит) для AES‑256!")
                    return
            else:
                key = generate_key()
                base64_key = urlsafe_b64encode(key).decode()
                messagebox.showinfo(
                    "Ключ сгенерирован автоматически",
            f"Ключ: {base64_key}\nСохраните его для расшифровки!"
        )

            if action == "encrypt":
                encrypt_file(key, input_file, output_file)
                self.status_label.config(text=f"Файл зашифрован: {output_file}", foreground="green")
            elif action == "decrypt":
                decrypt_file(key, input_file, output_file)
                self.status_label.config(text=f"Файл расшифрован: {output_file}", foreground="green")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка: {str(e)}")
            self.status_label.config(text="Ошибка выполнения операции", foreground="red")

if __name__ == '__main__':
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
