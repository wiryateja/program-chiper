import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np

# Key Definitions
# Vigenere
def vigenere_encrypt(plaintext, key):
    key = key.lower()
    key = (key * (len(plaintext) // len(key))) + key[:len(plaintext) % len(key)]
    ciphertext = ''
    for i in range(len(plaintext)):
        if plaintext[i].isalpha():
            shift = ord(key[i]) - ord('a')
            encrypted_char = chr((ord(plaintext[i].lower()) - ord('a') + shift) % 26 + ord('a'))
            ciphertext += encrypted_char
        else:
            ciphertext += plaintext[i]
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    key = key.lower()
    key = (key * (len(ciphertext) // len(key))) + key[:len(ciphertext) % len(key)]
    plaintext = ''
    for i in range(len(ciphertext)):
        if ciphertext[i].isalpha():
            shift = ord(key[i]) - ord('a')
            decrypted_char = chr((ord(ciphertext[i].lower()) - ord('a') - shift + 26) % 26 + ord('a'))
            plaintext += decrypted_char
        else:
            plaintext += ciphertext[i]
    return plaintext

# Playfair
def playfair_prepare_key(key):
    key = key.replace('j', 'i').lower()
    key = ''.join(sorted(set(key), key=key.index))  
    alphabet = 'abcdefghiklmnopqrstuvwxyz' 
    for char in alphabet:
        if char not in key:
            key += char
    return key

def playfair_encrypt(plaintext, key):
    key = playfair_prepare_key(key)
    plaintext = plaintext.replace('j', 'i').lower().replace(" ", "")
    if len(plaintext) % 2 != 0:
        plaintext += 'x'  
    ciphertext = ''
    for i in range(0, len(plaintext), 2):
        a, b = plaintext[i], plaintext[i + 1]
        row_a, col_a = key.index(a) // 5, key.index(a) % 5
        row_b, col_b = key.index(b) // 5, key.index(b) % 5
        if row_a == row_b:  
            ciphertext += key[row_a * 5 + (col_a + 1) % 5]
            ciphertext += key[row_b * 5 + (col_b + 1) % 5]
        elif col_a == col_b:  
            ciphertext += key[((row_a + 1) % 5) * 5 + col_a]
            ciphertext += key[((row_b + 1) % 5) * 5 + col_b]
        else: 
            ciphertext += key[row_a * 5 + col_b]
            ciphertext += key[row_b * 5 + col_a]
    return ciphertext

def playfair_decrypt(ciphertext, key):
    key = playfair_prepare_key(key)
    plaintext = ''
    for i in range(0, len(ciphertext), 2):
        a, b = ciphertext[i], ciphertext[i + 1]
        row_a, col_a = key.index(a) // 5, key.index(a) % 5
        row_b, col_b = key.index(b) // 5, key.index(b) % 5
        if row_a == row_b:  
            plaintext += key[row_a * 5 + (col_a - 1) % 5]
            plaintext += key[row_b * 5 + (col_b - 1) % 5]
        elif col_a == col_b: 
            plaintext += key[((row_a - 1) % 5) * 5 + col_a]
            plaintext += key[((row_b - 1) % 5) * 5 + col_b]
        else:  
            plaintext += key[row_a * 5 + col_b]
            plaintext += key[row_b * 5 + col_a]
    return plaintext

# Hill
def mod_inverse_matrix(matrix, mod):
    determinant = int(np.round(np.linalg.det(matrix)))  
    determinant_inv = pow(determinant, -1, mod)  
    matrix_mod_inv = (determinant_inv * np.round(determinant * np.linalg.inv(matrix)).astype(int) % mod) % mod
    return matrix_mod_inv

def hill_encrypt(plaintext, key_matrix):
    original_length = len(plaintext)  
    while len(plaintext) % 3 != 0:
        plaintext += 'x'  
    plaintext_vector = [ord(char) - ord('a') for char in plaintext]
    ciphertext = ''
    for i in range(0, len(plaintext_vector), 3):
        block = plaintext_vector[i:i+3]
        result = np.dot(key_matrix, block) % 26
        ciphertext += ''.join(chr(int(num) + ord('a')) for num in result)
    return ciphertext, original_length  

def hill_decrypt(ciphertext, key_matrix, original_length):
    key_matrix_inv = mod_inverse_matrix(key_matrix, 26)
    ciphertext_vector = [ord(char) - ord('a') for char in ciphertext]
    plaintext = ''
    for i in range(0, len(ciphertext_vector), 3):
        block = ciphertext_vector[i:i+3]
        result = np.dot(key_matrix_inv, block) % 26
        plaintext += ''.join(chr(int(num) + ord('a')) for num in result)
    return plaintext[:original_length]  

# File Upload Function
def upload_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, 'r') as file:
            input_text.delete("1.0", tk.END)
            input_text.insert(tk.END, file.read())

# Process Text Function
def process_text():
    plaintext = input_text.get("1.0", tk.END).strip()
    key = key_input.get().strip()
    
    if len(key) < 12:
        messagebox.showerror("Error", "Key must be at least 12 characters long.")
        return

    cipher_choice = cipher_var.get()
    
    if cipher_choice == 'Vigenere':
        result = vigenere_encrypt(plaintext, key) if action_var.get() == 'Encrypt' else vigenere_decrypt(plaintext, key)
    elif cipher_choice == 'Playfair':
        result = playfair_encrypt(plaintext, key) if action_var.get() == 'Encrypt' else playfair_decrypt(plaintext, key)
    elif cipher_choice == 'Hill':
        key_matrix = np.array([[6, 24, 1], [13, 16, 10], [20, 17, 15]])  
        if action_var.get() == 'Encrypt':
            ciphertext, original_length = hill_encrypt(plaintext, key_matrix)
            result = ciphertext
            output_text.original_length = original_length
        else:
            original_length = getattr(output_text, 'original_length', len(plaintext))
            result = hill_decrypt(plaintext, key_matrix, original_length)

    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, result)

# GUI Setup
root = tk.Tk()
root.title("Cryptography GUI")

cipher_var = tk.StringVar(value="Vigenere")
tk.Label(root, text="Choose Cipher").pack()
tk.Radiobutton(root, text="Vigenere", variable=cipher_var, value="Vigenere").pack()
tk.Radiobutton(root, text="Playfair", variable=cipher_var, value="Playfair").pack()
tk.Radiobutton(root, text="Hill", variable=cipher_var, value="Hill").pack()

tk.Label(root, text="Input Key (min 12 chars)").pack()
key_input = tk.Entry(root, width=50)
key_input.pack()

tk.Label(root, text="Input Text").pack()
input_text = tk.Text(root, height=5, width=50)
input_text.pack()

upload_button = tk.Button(root, text="Upload File", command=upload_file)
upload_button.pack()

action_var = tk.StringVar(value="Encrypt")
tk.Radiobutton(root, text="Encrypt", variable=action_var, value="Encrypt").pack()
tk.Radiobutton(root, text="Decrypt", variable=action_var, value="Decrypt").pack()

process_button = tk.Button(root, text="Process", command=process_text)
process_button.pack()

tk.Label(root, text="Output Text").pack()
output_text = tk.Text(root, height=5, width=50)
output_text.pack()

root.mainloop()
