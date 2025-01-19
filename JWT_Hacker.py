import base64
import hashlib
import zlib
from tkinter import ttk, Tk, Label, Text, Button, Frame, Scrollbar, StringVar, Entry, END, VERTICAL, filedialog
from tkinter.ttk import Style
import gzip
import codecs
import threading

# Define decoding functions
def decode_base64(data):
    try:
        return base64.urlsafe_b64decode(data + '===').decode('utf-8')
    except Exception:
        return None

def decode_base58(data):
    try:
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        base_count = len(alphabet)
        decoded = 0
        multi = 1
        for char in data[::-1]:
            decoded += multi * alphabet.index(char)
            multi *= base_count
        return decoded.to_bytes((decoded.bit_length() + 7) // 8, 'big').decode('utf-8')
    except Exception:
        return None

def decode_base91(data):
    try:
        import base91
        return base91.decode(data).decode('utf-8')
    except Exception:
        return None

def decode_rot13(data):
    try:
        return codecs.decode(data, 'rot_13')
    except Exception:
        return None

def decompress_gzip(data):
    try:
        return gzip.decompress(base64.b64decode(data)).decode('utf-8')
    except Exception:
        return None

def decompress_zlib(data):
    try:
        return zlib.decompress(base64.b64decode(data)).decode('utf-8')
    except Exception:
        return None

def hash_md5(data):
    try:
        return hashlib.md5(data.encode()).hexdigest()
    except Exception:
        return None

def hash_sha256(data):
    try:
        return hashlib.sha256(data.encode()).hexdigest()
    except Exception:
        return None

# Decoding operation mapping
operations = {
    "Base64": decode_base64,
    "Base58": decode_base58,
    "Base91": decode_base91,
    "ROT13": decode_rot13,
    "Gzip": decompress_gzip,
    "Zlib": decompress_zlib,
    "MD5 Hash": hash_md5,
    "SHA-256 Hash": hash_sha256
}

# Create the GUI
root = Tk()
root.title("Sci-Fi JWT Decoder")
root.geometry("900x600")
root.configure(bg="black")

# Style for hacker theme
style = Style()
style.configure("TLabel", background="black", foreground="lime", font=("Courier", 12))
style.configure("TButton", background="black", foreground="lime", font=("Courier", 12), borderwidth=2)
style.map("TButton", background=[("active", "lime")], foreground=[("active", "black")])

# Input frame
input_frame = Frame(root, bg="black")
input_frame.pack(pady=10)

ttk.Label(input_frame, text="Input JWT Token:", style="TLabel").grid(row=0, column=0, padx=5, pady=5, sticky="w")
input_text = Text(input_frame, height=5, width=80, bg="black", fg="lime", insertbackground="lime", font=("Courier", 12))
input_text.grid(row=1, column=0, padx=5, pady=5, columnspan=2)

# Output frame
output_frame = Frame(root, bg="black")
output_frame.pack(pady=10)

ttk.Label(output_frame, text="Decoded Output:", style="TLabel").grid(row=0, column=0, padx=5, pady=5, sticky="w")
output_text = Text(output_frame, height=15, width=80, bg="black", fg="lime", insertbackground="lime", font=("Courier", 12))
output_text.grid(row=1, column=0, padx=5, pady=5, columnspan=2)

scrollbar = Scrollbar(output_frame, orient=VERTICAL, command=output_text.yview)
scrollbar.grid(row=1, column=2, sticky="ns")
output_text["yscrollcommand"] = scrollbar.set

# Function to decode input
def decode_input():
    jwt_token = input_text.get("1.0", END).strip()
    if not jwt_token:
        output_text.insert(END, "No input provided!\n")
        return

    parts = jwt_token.split('.')
    if len(parts) != 3:
        output_text.insert(END, "Invalid JWT structure!\n")
        return

    header, payload, signature = parts
    output_text.delete("1.0", END)

    for part, label in zip([header, payload], ["Header", "Payload"]):
        output_text.insert(END, f"{label}:\n")
        for name, func in operations.items():
            result = func(part)
            if result:
                output_text.insert(END, f"  {name}:\n{result}\n\n")

    output_text.insert(END, f"Signature (Base64):\n{signature}\n")

# Buttons
decode_button = ttk.Button(root, text="Decode", command=lambda: threading.Thread(target=decode_input).start(), style="TButton")
decode_button.pack(pady=10)

save_button = ttk.Button(root, text="Save Output", command=lambda: save_output(), style="TButton")
save_button.pack(pady=10)

def save_output():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(output_text.get("1.0", END))

# Run the GUI
root.mainloop()
