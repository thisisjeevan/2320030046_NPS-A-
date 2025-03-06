import cv2
import numpy as np
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Generate a New AES Key (Automatically)
def generate_aes_key():
    return os.urandom(16)  # Generates a 16-byte random key

# Function to Encrypt Message
def encrypt_message(plaintext, key):
    iv = os.urandom(16)  # Generate IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext  # Return IV + Encrypted Message

# Function to Decrypt Message
def decrypt_message(ciphertext, key):
    iv = ciphertext[:16]  # Extract IV
    encrypted_data = ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove Padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_text = unpadder.update(decrypted_padded) + unpadder.finalize()

    return decrypted_text.decode()

# Convert message to binary
def message_to_binary(message):
    return ''.join(format(byte, '08b') for byte in message)

# Function to Encode (Hide) Message in Image
def encode_message():
    global input_image_path, AES_KEY

    # Get message from user
    secret_message = message_entry.get()
    if not secret_message:
        messagebox.showerror("Error", "Please enter a message to hide.")
        return

    AES_KEY = generate_aes_key()  # Generate a new AES key
    encrypted_message = encrypt_message(secret_message, AES_KEY)
    binary_secret = message_to_binary(encrypted_message)

    # Read Image
    img = cv2.imread(input_image_path)
    if img is None:
        messagebox.showerror("Error", "Failed to load image.")
        return

    data_index = 0
    binary_secret_length = len(binary_secret)

    for row in img:
        for pixel in row:
            for color in range(3):  # Modify R, G, B values
                if data_index < binary_secret_length:
                    bit = int(binary_secret[data_index])  # Ensure bit is 0 or 1
                    pixel[color] = np.uint8((int(pixel[color]) & ~1) | (bit & 1))  # Modify only LSB
                    data_index += 1
                else:
                    break
    
    if data_index < binary_secret_length:
        messagebox.showerror("Error", "Message is too large for this image.")
        return

    # Ask User Where to Save the Image
    output_image_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Files", "*.png")])
    if not output_image_path:
        return

    cv2.imwrite(output_image_path, img)

    # Show the AES Key for the User to Save
    messagebox.showinfo("Success", f"Message hidden successfully!\n\nYour AES Key (Save it!):\n{AES_KEY.hex()}")

# Convert binary to bytes
def binary_to_bytes(binary_data):
    byte_list = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    return bytes(int(byte, 2) for byte in byte_list)

# Function to Decode (Extract) Message from Image
def decode_message():
    global input_image_path

    # Read Image
    img = cv2.imread(input_image_path)
    binary_data = ""

    for row in img:
        for pixel in row:
            for color in range(3):  # Extract LSB from R, G, B values
                binary_data += str(pixel[color] & 1)

    encrypted_message = binary_to_bytes(binary_data)

    # Ask User for the AES Key
    user_key_hex = simpledialog.askstring("Enter Key", "Enter the AES Key to decrypt the message:")
    if not user_key_hex:
        messagebox.showerror("Error", "No key entered.")
        return

    try:
        user_key = bytes.fromhex(user_key_hex)  # Convert Hex Key to Bytes
        decrypted_message = decrypt_message(encrypted_message, user_key)
        messagebox.showinfo("Hidden Message", f"Extracted Message: {decrypted_message}")
    except:
        messagebox.showerror("Error", "Wrong Key! Unable to decrypt.")

# Function to Load Image
def load_image():
    global input_image_path, img_label

    input_image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if input_image_path:
        img = Image.open(input_image_path)
        img = img.resize((250, 250))
        img = ImageTk.PhotoImage(img)
        img_label.config(image=img)
        img_label.image = img

# Create GUI Window
root = tk.Tk()
root.title("Image Steganography with AES Encryption")
root.geometry("500x650")
root.resizable(False, False)

# Heading Label
title_label = tk.Label(root, text="Image Steganography", font=("Arial", 16, "bold"))
title_label.pack(pady=10)

# Image Selection Button
btn_load_image = tk.Button(root, text="Select Image", command=load_image)
btn_load_image.pack(pady=10)

# Display Selected Image
img_label = tk.Label(root)
img_label.pack(pady=10)

# Message Entry
message_label = tk.Label(root, text="Enter Secret Message:")
message_label.pack()
message_entry = tk.Entry(root, width=50)
message_entry.pack(pady=5)

# Encode & Decode Buttons
btn_encode = tk.Button(root, text="Hide Message", command=encode_message, bg="green", fg="white")
btn_encode.pack(pady=5)

btn_decode = tk.Button(root, text="Extract Message", command=decode_message, bg="blue", fg="white")
btn_decode.pack(pady=5)

# Run the Application
root.mainloop()
