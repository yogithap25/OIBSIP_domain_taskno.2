import tkinter as tk
from tkinter import ttk, messagebox
import string
import secrets

def build_char_pool(use_upper, use_lower, use_digits, use_symbols):
    pool = ""
    if use_upper:
        pool += string.ascii_uppercase
    if use_lower:
        pool += string.ascii_lowercase
    if use_digits:
        pool += string.digits
    if use_symbols:
        pool += string.punctuation
    return pool

def generate_secure_password(length, use_upper, use_lower, use_digits, use_symbols):
    selected_types = []
    if use_upper:
        selected_types.append(string.ascii_uppercase)
    if use_lower:
        selected_types.append(string.ascii_lowercase)
    if use_digits:
        selected_types.append(string.digits)
    if use_symbols:
        selected_types.append(string.punctuation)

    if not selected_types:
        raise ValueError("Select at least one character type.")

    MIN_LENGTH = 8
    if length < MIN_LENGTH:
        raise ValueError(f"Password length must be at least {MIN_LENGTH}.")

    if length < len(selected_types):
        raise ValueError(
            f"Length must be at least {len(selected_types)} "
            "to include all selected character types."
        )

    pool = build_char_pool(use_upper, use_lower, use_digits, use_symbols)
    if not pool:
        raise ValueError("No characters available to generate a password.")

    password_chars = []

    for charset in selected_types:
        password_chars.append(secrets.choice(charset))

    remaining = length - len(password_chars)
    for _ in range(remaining):
        password_chars.append(secrets.choice(pool))

    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)

class PasswordGeneratorApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Password Generator")
        self.resizable(False, False)

        self.length_var = tk.IntVar(value=12)
        self.use_upper = tk.BooleanVar(value=True)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.password_var = tk.StringVar(value="")

        self.build_ui()

    def build_ui(self):
        pad = {"padx": 8, "pady": 6}

        main = ttk.Frame(self, padding=12)
        main.grid(row=0, column=0)

        ttk.Label(main, text="Generated Password:").grid(
            row=0, column=0, sticky="w", **pad
        )

        self.pass_entry = ttk.Entry(
            main, textvariable=self.password_var, width=40, font=("Consolas", 12)
        )
        self.pass_entry.grid(row=1, column=0, sticky="w", **pad)

        ttk.Button(main, text="Copy", command=self.copy).grid(
            row=1, column=1, sticky="w", **pad
        )

        opt = ttk.LabelFrame(main, text="Options")
        opt.grid(row=2, column=0, columnspan=2, sticky="ew", **pad)

        ttk.Label(opt, text="Length:").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        self.spin_len = ttk.Spinbox(
            opt,
            from_=4,
            to=64,
            textvariable=self.length_var,
            width=5,
        )
        self.spin_len.grid(row=0, column=1, sticky="w")

        ttk.Checkbutton(
            opt, text="Include Uppercase (A-Z)", variable=self.use_upper
        ).grid(row=1, column=0, sticky="w", padx=8, pady=4)

        ttk.Checkbutton(
            opt, text="Include Lowercase (a-z)", variable=self.use_lower
        ).grid(row=1, column=1, sticky="w", padx=8, pady=4)

        ttk.Checkbutton(
            opt, text="Include Digits (0-9)", variable=self.use_digits
        ).grid(row=2, column=0, sticky="w", padx=8, pady=4)

        ttk.Checkbutton(
            opt, text="Include Symbols (!@#...)", variable=self.use_symbols
        ).grid(row=2, column=1, sticky="w", padx=8, pady=4)

        ttk.Button(main, text="Generate", command=self.generate).grid(
            row=3, column=0, sticky="w", **pad
        )

    def generate(self):
        try:
            length = int(self.length_var.get())
            pwd = generate_secure_password(
                length,
                self.use_upper.get(),
                self.use_lower.get(),
                self.use_digits.get(),
                self.use_symbols.get(),
            )
            self.password_var.set(pwd)
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def copy(self):
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showinfo("Info", "Generate a password first.")
            return

        self.clipboard_clear()
        self.clipboard_append(pwd)
        self.update()
        messagebox.showinfo("Copied", "Password copied to clipboard.")

if __name__ == "__main__":
    app = PasswordGeneratorApp()
    app.mainloop()