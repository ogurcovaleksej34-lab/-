import os
import argparse
import sys
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

def main():
    parser = argparse.ArgumentParser(
        description='Шифровальщик файлов с использованием AES-256-CBC.'
    )
    parser.add_argument(
        'action',
        choices=['encrypt', 'decrypt'],
        help='Действие: encrypt — зашифровать, decrypt — расшифровать'
    )
    parser.add_argument(
        'input_file',
        help='Путь к входному файлу'
    )
    parser.add_argument(
        'output_file',
        help='Путь для сохранения результата'
    )
    parser.add_argument(
        '--key',
        default=None,
        help='Base64‑кодированный ключ (32 байта для AES‑256). Если не указан, генерируется новый.'
    )

    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        print(f'Ошибка: Файл "{args.input_file}" не найден.', file=sys.stderr)
        sys.exit(1)

    if args.key is None:
        key = generate_key()
        print(f'Сгенерирован новый ключ: {urlsafe_b64encode(key).decode()}')
        print('Сохраните этот ключ — он понадобится для расшифровки!')
    else:
        try:
            key = urlsafe_b64decode(args.key)
            if len(key) != 32:
                print('Ошибка: Ключ должен быть ровно 32 байта (256 бит) для AES‑256.', file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f'Ошибка декодирования ключа: {e}', file=sys.stderr)
            sys.exit(1)

    try:
        if args.action == 'encrypt':
            encrypt_file(key, args.input_file, args.output_file)
            print(f'Файл успешно зашифрован: {args.output_file}')
        elif args.action == 'decrypt':
            decrypt_file(key, args.input_file, args.output_file)
            print(f'Файл успешно расшифрован: {args.output_file}')
    except Exception as e:
        print(f'Ошибка при выполнении операции: {e}', file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
