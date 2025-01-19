from tkinter import ttk, Tk, Text, Frame, Scrollbar, END, VERTICAL, filedialog, Label
from tkinter.ttk import Style
import threading
from jwt_hacker.decoder import operations

# Create the GUI
def main():
    root = Tk()
    root.title("JWT Hacker")
    root.geometry("900x600")
    root.configure(bg="black")

    # Style for hacker theme
    style = Style()
    style.configure("TLabel", background="black", foreground="lime", font=("Courier", 12))
    style.configure("TButton", background="black", foreground="lime", font=("Courier", 12), borderwidth=2)
    style.map("TButton", background=[("active", "lime")], foreground=[("active", "black")])

    # Header section for additional information
    header_frame = Frame(root, bg="black")
    header_frame.pack(fill="x")

    # Organization Name (Top Left)
    org_label = Label(header_frame, text="Grey Node Studios", fg="lime", bg="black", font=("Courier", 14, "bold"), anchor="w")
    org_label.pack(side="left", padx=10)

    # Coder Name (Top Right)
    coder_label = Label(header_frame, text="Coder: Z3r0 S3c", fg="lime", bg="black", font=("Courier", 14, "bold"), anchor="e")
    coder_label.pack(side="right", padx=10)

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
    ttk.Button(root, text="Decode", command=lambda: threading.Thread(target=decode_input).start(), style="TButton").pack(pady=10)

    def save_output():
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(output_text.get("1.0", END))

    ttk.Button(root, text="Save Output", command=save_output, style="TButton").pack(pady=10)

    # Run the GUI
    root.mainloop()
