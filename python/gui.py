import tkinter as tk
from tkinter import messagebox
from password_manager.seed import (
    verify_seed_phrase,
    derive_keys,
    generate_seed_phrase,
)
from pathlib import Path
import json
from password_manager.password import generate_password
from password_manager.nostr_utils import (
    backup_to_nostr,
    restore_from_nostr,
    restore_history_from_nostr,
)


class PasswordManagerGUI(tk.Tk):
    def __init__(self, debug: bool = False):
        super().__init__()
        self.debug = debug
        self.title("SecureVault Manager")
        # Original interface was 400x400 which became cramped as new
        # functionality was added. Increase the height to provide more space
        # for additional controls while keeping the width unchanged.
        self.geometry("400x600")

        # Seed phrase entry
        tk.Label(self, text="Seed Phrase").pack()
        self.seed_entry = tk.Entry(self, width=50)
        self.seed_entry.pack(pady=5)
        tk.Button(self, text="New Mnemonic", command=self.new_mnemonic).pack(pady=5)
        tk.Button(self, text="Verify Seed", command=self.verify_seed).pack(pady=5)

        # Username and site for password generation
        tk.Label(self, text="Username").pack()
        self.user_entry = tk.Entry(self, width=40)
        self.user_entry.pack(pady=5)

        tk.Label(self, text="Site").pack()
        self.site_entry = tk.Entry(self, width=40)
        self.site_entry.pack(pady=5)

        tk.Label(self, text="Nonce").pack()
        self.nonce_entry = tk.Entry(self, width=10)
        self.nonce_entry.insert(0, "0")
        self.nonce_entry.pack(pady=5)

        tk.Label(self, text="Relay URLs (comma separated)").pack()
        self.relay_entry = tk.Entry(self, width=50)
        self.relay_entry.pack(pady=5)

        tk.Button(self, text="Generate Password", command=self.generate).pack(pady=5)
        self.password_var = tk.StringVar()
        tk.Entry(self, textvariable=self.password_var, width=40).pack(pady=5)

        tk.Button(self, text="Backup", command=self.backup).pack(pady=5)
        tk.Button(self, text="Restore", command=self.restore).pack(pady=5)
        tk.Button(self, text="History", command=self.history).pack(pady=5)
        tk.Button(self, text="Edit Nonces", command=self.edit_nonces).pack(pady=5)

        self.keys = None
        self.nonces_file = Path(__file__).resolve().parent / "nonces.json"
        self.nonces = {}
        if self.nonces_file.exists():
            try:
                self.nonces = json.loads(self.nonces_file.read_text())
            except Exception:
                self.nonces = {}

        self.user_entry.bind("<FocusOut>", lambda e: self.update_nonce_field())
        self.site_entry.bind("<FocusOut>", lambda e: self.update_nonce_field())

    def verify_seed(self):
        phrase = self.seed_entry.get().strip()
        if verify_seed_phrase(phrase):
            self.keys = derive_keys(phrase)
            messagebox.showinfo("Seed", "Seed phrase is valid")
        else:
            messagebox.showerror("Seed", "Invalid seed phrase")

    def generate(self):
        if not self.keys:
            messagebox.showerror("Error", "Verify the seed first")
            return
        user = self.user_entry.get().strip()
        site = self.site_entry.get().strip()
        try:
            nonce = int(self.nonce_entry.get())
        except ValueError:
            nonce = 0
        pwd = generate_password(self.keys["private_key"], user, site, nonce)
        self.password_var.set(pwd)

        if user and site:
            self.nonces.setdefault(user, {})[site] = nonce
            self.nonces_file.write_text(json.dumps(self.nonces, indent=2))

    def backup(self):
        if not self.keys:
            messagebox.showerror("Error", "Verify the seed first")
            return
        relay_urls = [u.strip() for u in self.relay_entry.get().split(',') if u.strip()] or None
        data = {
            "user": self.user_entry.get().strip(),
            "site": self.site_entry.get().strip(),
            "nonce": self.nonce_entry.get().strip(),
            "password": self.password_var.get(),
        }
        event_id = backup_to_nostr(
            self.keys["private_key"], data, relay_urls=relay_urls, debug=self.debug
        )
        messagebox.showinfo("Backup", f"Backup stored with id {event_id}")

    def restore(self):
        if not self.keys:
            messagebox.showerror("Error", "Verify the seed first")
            return
        relay_urls = [u.strip() for u in self.relay_entry.get().split(',') if u.strip()] or None
        try:
            data = restore_from_nostr(
                self.keys["private_key"], relay_urls=relay_urls, debug=self.debug
            )
        except Exception as exc:
            messagebox.showerror("Restore", str(exc))
            return
        self.user_entry.delete(0, tk.END)
        self.user_entry.insert(0, data.get("user", ""))
        self.site_entry.delete(0, tk.END)
        self.site_entry.insert(0, data.get("site", ""))
        self.nonce_entry.delete(0, tk.END)
        self.nonce_entry.insert(0, data.get("nonce", "0"))
        self.password_var.set(data.get("password", ""))
        messagebox.showinfo("Restore", "Backup restored")

    def history(self):
        if not self.keys:
            messagebox.showerror("Error", "Verify the seed first")
            return
        relay_urls = [u.strip() for u in self.relay_entry.get().split(',') if u.strip()] or None
        history = restore_history_from_nostr(
            self.keys["private_key"], relay_urls=relay_urls, debug=self.debug
        )
        win = tk.Toplevel(self)
        win.title("Nostr History")
        text = tk.Text(win, width=60, height=20)
        text.pack()
        text.insert(tk.END, json.dumps(history, indent=2))

    def edit_nonces(self):
        win = tk.Toplevel(self)
        win.title("Edit Nonces")
        text = tk.Text(win, width=60, height=20)
        text.pack()
        text.insert(tk.END, json.dumps(self.nonces, indent=2))

        def save():
            try:
                self.nonces = json.loads(text.get("1.0", tk.END))
                self.nonces_file.write_text(json.dumps(self.nonces, indent=2))
                win.destroy()
                self.update_nonce_field()
            except Exception as exc:
                messagebox.showerror("Nonces", str(exc))

        tk.Button(win, text="Save", command=save).pack()

    def update_nonce_field(self):
        user = self.user_entry.get().strip()
        site = self.site_entry.get().strip()
        nonce = self.nonces.get(user, {}).get(site)
        if nonce is not None:
            self.nonce_entry.delete(0, tk.END)
            self.nonce_entry.insert(0, str(nonce))

    def new_mnemonic(self):
        phrase = generate_seed_phrase()
        self.seed_entry.delete(0, tk.END)
        self.seed_entry.insert(0, phrase)
        self.keys = derive_keys(phrase)
        messagebox.showinfo("Seed", "New seed phrase generated")


if __name__ == "__main__":
    app = PasswordManagerGUI()
    app.mainloop()
