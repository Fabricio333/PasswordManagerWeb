import tkinter as tk
from tkinter import messagebox
from password_manager.seed import (
    verify_seed_phrase,
    derive_keys,
    generate_seed_phrase,
)
from pathlib import Path
import json
from urllib.parse import urlparse
from password_manager.password import generate_password
from password_manager.nostr_utils import (
    backup_to_nostr,
    backup_nonces_to_nostr,
    restore_from_nostr,
    restore_history_from_nostr,
    load_nonces,
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
        self.nonces = {}

        self.user_entry.bind("<FocusOut>", lambda e: self.update_nonce_field())
        self.site_entry.bind("<FocusOut>", lambda e: self.update_nonce_field())

    def verify_seed(self):
        phrase = self.seed_entry.get().strip()
        if verify_seed_phrase(phrase):
            self.keys = derive_keys(phrase)
            messagebox.showinfo("Seed", "Seed phrase is valid")
            # Load nonces for this pubkey from local/relay backups
            try:
                relay_urls = [u.strip() for u in self.relay_entry.get().split(',') if u.strip()] or None
                self.nonces = load_nonces(
                    self.keys["private_key"], relay_urls=relay_urls, debug=self.debug
                )
                # If the newest history entry is a nonces snapshot from a relay,
                # clone it to the local backup so that offline usage sees the
                # latest remote state.
                try:
                    latest = restore_history_from_nostr(
                        self.keys["private_key"],
                        relay_urls=relay_urls,
                        debug=self.debug,
                        limit=1,
                    )
                except Exception:
                    latest = []
                if latest:
                    item = latest[0]
                    snapshot = None
                    if isinstance(item, dict):
                        snapshot = item.get("users") or item.get("nonces")
                    if snapshot and item.get("source") == "relay":
                        self.nonces = snapshot
                        backup_nonces_to_nostr(
                            self.keys["private_key"],
                            self.nonces,
                            relay_urls=[],
                            debug=self.debug,
                        )
                self.update_nonce_field()
            except Exception:
                pass
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
        result = backup_to_nostr(
            self.keys["private_key"],
            data,
            relay_urls=relay_urls,
            debug=self.debug,
            return_status=True,
        )
        # result is a dict when return_status=True
        event_id = result["event_id"]
        if result.get("published"):
            messagebox.showinfo(
                "Backup",
                f"Backup stored and published (id {event_id})",
            )
        else:
            messagebox.showinfo(
                "Backup",
                f"No relay connection; local encrypted backup created only (id {event_id})",
            )

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
        # Retrieve the 5 latest events (merged: relays, local, session)
        history = restore_history_from_nostr(
            self.keys["private_key"], relay_urls=relay_urls, debug=self.debug, limit=5
        )

        # If any nonces snapshot exists in the retrieved history, overwrite the
        # current nonce mapping and persist it locally for offline use.
        for item in history:
            snapshot = None
            if isinstance(item, dict):
                snapshot = item.get("users") or item.get("nonces")
            if snapshot:
                self.nonces = snapshot
                backup_nonces_to_nostr(
                    self.keys["private_key"],
                    self.nonces,
                    relay_urls=[],
                    debug=self.debug,
                )
                self.update_nonce_field()
                break

        win = tk.Toplevel(self)
        win.title("Nostr History (select to restore)")

        # Listbox to show entries with timestamp and summary
        frame = tk.Frame(win)
        frame.pack(fill=tk.BOTH, expand=True)

        listbox = tk.Listbox(frame, width=60, height=12)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL, command=listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        listbox.config(yscrollcommand=scrollbar.set)

        def fmt_item(item):
            ts = int(item.get("created_at", 0))
            try:
                import time as _t
                human = _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime(ts)) if ts else ""
            except Exception:
                human = str(ts)
            src = item.get("source", "")
            relay = item.get("relay")
            if src == "relay" and relay:
                try:
                    src_disp = urlparse(relay).netloc or relay
                except Exception:
                    src_disp = relay
            else:
                src_disp = src
            eid = item.get("event_id", "")
            # If this is a nonces snapshot, present a tailored summary
            if isinstance(item, dict) and (
                "nonces" in item or "users" in item
            ):
                source = item.get("users") or item.get("nonces")
                try:
                    count = len(source or {})
                except Exception:
                    count = 0
                return f"{human}  NONCES snapshot ({count} entries)  [{src_disp}]  id={eid[:10]}..."
            # Otherwise treat as a standard password backup event
            user = item.get("user", "")
            site = item.get("site", "")
            nonce = item.get("nonce", "")
            return f"{human}  {user}@{site} nonce={nonce}  [{src_disp}]  id={eid[:10]}..."

        for it in history:
            listbox.insert(tk.END, fmt_item(it))

        # Restore selected item
        def do_restore():
            idx = listbox.curselection()
            if not idx:
                messagebox.showinfo("History", "Select an event to restore")
                return
            item = history[idx[0]]
            # If the item is a nonces snapshot, update nonces and refresh field
            snapshot = None
            if isinstance(item, dict):
                snapshot = item.get("users") or item.get("nonces")
            if snapshot is not None:
                try:
                    self.nonces = snapshot or {}
                    backup_nonces_to_nostr(
                        self.keys["private_key"],
                        self.nonces,
                        relay_urls=[],
                        debug=self.debug,
                    )
                    self.update_nonce_field()
                    messagebox.showinfo(
                        "Restore", f"Loaded NONCES snapshot {item.get('event_id','')}"
                    )
                except Exception as exc:
                    messagebox.showerror("Restore", f"Failed to load nonces: {exc}")
            else:
                # Load fields into the main form for password backup
                user = item.get("user", "")
                site = item.get("site", "")
                nonce_val = int(item.get("nonce", 0))
                self.user_entry.delete(0, tk.END)
                self.user_entry.insert(0, user)
                self.site_entry.delete(0, tk.END)
                self.site_entry.insert(0, site)
                self.nonce_entry.delete(0, tk.END)
                self.nonce_entry.insert(0, str(nonce_val))
                self.password_var.set(item.get("password", ""))
                # Overwrite nonce mapping with the restored event details
                if user and site:
                    self.nonces.setdefault(user, {})[site] = nonce_val
                    backup_nonces_to_nostr(
                        self.keys["private_key"],
                        self.nonces,
                        relay_urls=[],
                        debug=self.debug,
                    )
                messagebox.showinfo("Restore", f"Loaded event {item.get('event_id','')}")
            win.destroy()

        btn_frame = tk.Frame(win)
        btn_frame.pack(fill=tk.X)
        tk.Button(btn_frame, text="Restore Selected", command=do_restore).pack(side=tk.RIGHT, padx=5, pady=5)

        def on_double_click(event):
            do_restore()

        listbox.bind("<Double-Button-1>", on_double_click)

    def edit_nonces(self):
        win = tk.Toplevel(self)
        win.title("Edit Nonces")
        text = tk.Text(win, width=60, height=20)
        text.pack()
        text.insert(tk.END, json.dumps(self.nonces, indent=2))

        def save():
            try:
                self.nonces = json.loads(text.get("1.0", tk.END))
                # Save nonces snapshot locally and publish to relays (if reachable)
                relay_urls = [u.strip() for u in self.relay_entry.get().split(',') if u.strip()] or None
                result = backup_nonces_to_nostr(
                    self.keys["private_key"],
                    self.nonces,
                    relay_urls=relay_urls,
                    debug=self.debug,
                    return_status=True,
                )
                if result.get("published"):
                    messagebox.showinfo("Nonces", f"Nonces saved and published (id {result['event_id']})")
                else:
                    messagebox.showinfo("Nonces", f"No relay connection; local encrypted nonces backup created only (id {result['event_id']})")
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
        # Generating a new mnemonic should be entirely local.  Avoid any
        # interaction with Nostr relays or backups for a freshly created key
        # so no relay backup is created implicitly.
        self.nonces = {}
        self.update_nonce_field()
        messagebox.showinfo("Seed", "New seed phrase generated")


if __name__ == "__main__":
    app = PasswordManagerGUI()
    app.mainloop()
