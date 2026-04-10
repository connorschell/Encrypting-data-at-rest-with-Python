#!/usr/bin/env python3
"""
CYBR448 Final Project - AES Encryption Tool GUI
Wizard-style Tkinter interface with Encrypt / Decrypt tabs.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import sys
import os
import getpass
from pathlib import Path
from io import StringIO

# ── Import core logic from encrypt.py ────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from encrypt import (
    derive_key, random_key, key_from_hex,
    encrypt_file, decrypt_file,
    collect_files, enc_output_path, dec_output_path,
    zip_folder, unzip_to, _unpack_header,
    PBKDF2_ITER, SALT_SIZE, IV_SIZE,
)
import secrets, tempfile, zipfile, shutil

# ── Theme colors ──────────────────────────────────────────────────────────────
BG        = "#1e1e2e"
BG2       = "#2a2a3e"
BG3       = "#313145"
ACCENT    = "#7c6af7"
ACCENT2   = "#a89cf7"
FG        = "#cdd6f4"
FG2       = "#a6adc8"
GREEN     = "#a6e3a1"
RED       = "#f38ba8"
YELLOW    = "#f9e2af"
FONT      = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_H    = ("Segoe UI", 13, "bold")
FONT_SM   = ("Segoe UI", 9)

# ── Helpers ───────────────────────────────────────────────────────────────────

def styled_button(parent, text, command, color=ACCENT, width=18):
    return tk.Button(parent, text=text, command=command,
                     bg=color, fg="white", activebackground=ACCENT2,
                     activeforeground="white", relief="flat",
                     font=FONT_BOLD, cursor="hand2", padx=10, pady=6, width=width)

def styled_label(parent, text, fg=FG, font=FONT):
    return tk.Label(parent, text=text, bg=BG2, fg=fg, font=font, anchor="w")

def styled_entry(parent, show=None, width=40):
    e = tk.Entry(parent, bg=BG3, fg=FG, insertbackground=FG,
                 relief="flat", font=FONT, width=width, show=show)
    e.configure(highlightthickness=1, highlightbackground=ACCENT,
                highlightcolor=ACCENT2)
    return e

def styled_combo(parent, values, width=20):
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Dark.TCombobox",
                    fieldbackground=BG3, background=BG3,
                    foreground=FG, selectbackground=ACCENT,
                    selectforeground="white", arrowcolor=ACCENT2)
    c = ttk.Combobox(parent, values=values, width=width,
                     state="readonly", style="Dark.TCombobox", font=FONT)
    return c

def card(parent, title=None):
    """A dark rounded-ish card frame."""
    outer = tk.Frame(parent, bg=BG, padx=2, pady=2)
    inner = tk.Frame(outer, bg=BG2, padx=16, pady=14)
    inner.pack(fill="both", expand=True)
    if title:
        tk.Label(inner, text=title, bg=BG2, fg=ACCENT2,
                 font=FONT_H, anchor="w").pack(fill="x", pady=(0, 10))
    outer.pack(fill="x", padx=10, pady=6)
    return inner

# ── Log widget ────────────────────────────────────────────────────────────────

class LogBox(tk.Text):
    def __init__(self, parent):
        super().__init__(parent, bg=BG3, fg=FG, font=("Consolas", 9),
                         relief="flat", height=8, wrap="word",
                         state="disabled", padx=8, pady=8)
        self.tag_config("ok",   foreground=GREEN)
        self.tag_config("err",  foreground=RED)
        self.tag_config("warn", foreground=YELLOW)
        self.tag_config("info", foreground=ACCENT2)

    def write(self, msg, tag="ok"):
        self.configure(state="normal")
        self.insert("end", msg + "\n", tag)
        self.see("end")
        self.configure(state="disabled")

    def clear(self):
        self.configure(state="normal")
        self.delete("1.0", "end")
        self.configure(state="disabled")

# ══════════════════════════════════════════════════════════════════════════════
# ENCRYPT WIZARD
# ══════════════════════════════════════════════════════════════════════════════

class EncryptWizard(tk.Frame):
    STEPS = ["1  Target", "2  Key Setup", "3  Options", "4  Encrypt"]

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self.step = 0
        self.targets = []        # list of Path
        self.key_mode = tk.StringVar(value="password")
        self.key_bits = tk.StringVar(value="256")
        self.key_source = tk.StringVar(value="generate")
        self.hex_key_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.confirm_var = tk.StringVar()
        self.delete_original = tk.BooleanVar(value=False)
        self.zip_folders = tk.BooleanVar(value=False)
        self.out_dir_var = tk.StringVar()

        self._build_header()
        self._build_steps()
        self._build_nav()
        self._show_step(0)

    # ── Header / step indicator
    def _build_header(self):
        hdr = tk.Frame(self, bg=BG, pady=10)
        hdr.pack(fill="x")
        self.step_labels = []
        for i, name in enumerate(self.STEPS):
            lbl = tk.Label(hdr, text=name, bg=BG, fg=FG2, font=FONT_SM, padx=8)
            lbl.pack(side="left")
            self.step_labels.append(lbl)
            if i < len(self.STEPS) - 1:
                tk.Label(hdr, text="›", bg=BG, fg=FG2, font=FONT_SM).pack(side="left")

    def _update_step_indicator(self):
        for i, lbl in enumerate(self.step_labels):
            if i == self.step:
                lbl.config(fg=ACCENT2, font=FONT_BOLD)
            elif i < self.step:
                lbl.config(fg=GREEN, font=FONT_SM)
            else:
                lbl.config(fg=FG2, font=FONT_SM)

    # ── Step frames
    def _build_steps(self):
        self.frames = [
            self._step_target(),
            self._step_key(),
            self._step_options(),
            self._step_run(),
        ]

    def _step_target(self):
        f = tk.Frame(self, bg=BG)
        c = card(f, "Select files or folders to encrypt")

        self.target_listbox = tk.Listbox(c, bg=BG3, fg=FG, selectbackground=ACCENT,
                                          font=FONT, relief="flat", height=5,
                                          highlightthickness=1, highlightbackground=ACCENT)
        self.target_listbox.pack(fill="x", pady=(0, 8))

        btns = tk.Frame(c, bg=BG2)
        btns.pack(fill="x")
        styled_button(btns, "＋ Add File(s)", self._add_files, width=14).pack(side="left", padx=(0,6))
        styled_button(btns, "＋ Add Folder", self._add_folder, width=14).pack(side="left", padx=(0,6))
        styled_button(btns, "✕ Remove", self._remove_target, color="#e06c75", width=10).pack(side="left")
        return f

    def _step_key(self):
        f = tk.Frame(self, bg=BG)
        c = card(f, "Choose key type")

        styled_label(c, "Key Mode:").pack(fill="x")
        km = tk.Frame(c, bg=BG2); km.pack(fill="x", pady=(2,10))
        tk.Radiobutton(km, text="Password  (PBKDF2-HMAC-SHA256)", variable=self.key_mode,
                       value="password", bg=BG2, fg=FG, selectcolor=BG3,
                       activebackground=BG2, font=FONT,
                       command=self._refresh_key_ui).pack(anchor="w")
        tk.Radiobutton(km, text="Raw cryptographic key  (AES)", variable=self.key_mode,
                       value="raw", bg=BG2, fg=FG, selectcolor=BG3,
                       activebackground=BG2, font=FONT,
                       command=self._refresh_key_ui).pack(anchor="w")

        styled_label(c, "Key Size (bits):").pack(fill="x", pady=(4,2))
        bits_f = tk.Frame(c, bg=BG2); bits_f.pack(fill="x", pady=(0,10))
        for b in ["128", "192", "256"]:
            tk.Radiobutton(bits_f, text=f"AES-{b}", variable=self.key_bits,
                           value=b, bg=BG2, fg=FG, selectcolor=BG3,
                           activebackground=BG2, font=FONT).pack(side="left", padx=(0,16))

        # Password fields
        self.pw_frame = tk.Frame(c, bg=BG2)
        styled_label(self.pw_frame, "Password:").pack(fill="x")
        tk.Entry(self.pw_frame, textvariable=self.password_var, show="●",
                 bg=BG3, fg=FG, insertbackground=FG, relief="flat", font=FONT,
                 highlightthickness=1, highlightbackground=ACCENT).pack(fill="x", pady=(2,8))
        styled_label(self.pw_frame, "Confirm Password:").pack(fill="x")
        tk.Entry(self.pw_frame, textvariable=self.confirm_var, show="●",
                 bg=BG3, fg=FG, insertbackground=FG, relief="flat", font=FONT,
                 highlightthickness=1, highlightbackground=ACCENT).pack(fill="x", pady=(2,0))

        # Raw key fields
        self.raw_frame = tk.Frame(c, bg=BG2)
        styled_label(self.raw_frame, "Key Source:").pack(fill="x")
        ks_f = tk.Frame(self.raw_frame, bg=BG2); ks_f.pack(fill="x", pady=(2,8))
        tk.Radiobutton(ks_f, text="Generate automatically", variable=self.key_source,
                       value="generate", bg=BG2, fg=FG, selectcolor=BG3,
                       activebackground=BG2, font=FONT,
                       command=self._refresh_key_ui).pack(anchor="w")
        tk.Radiobutton(ks_f, text="Provide my own hex key", variable=self.key_source,
                       value="provide", bg=BG2, fg=FG, selectcolor=BG3,
                       activebackground=BG2, font=FONT,
                       command=self._refresh_key_ui).pack(anchor="w")
        self.hex_label = styled_label(self.raw_frame, "Hex Key:")
        self.hex_label.pack(fill="x")
        self.hex_entry = tk.Entry(self.raw_frame, textvariable=self.hex_key_var,
                                  bg=BG3, fg=FG, insertbackground=FG, relief="flat",
                                  font=("Consolas", 9),
                                  highlightthickness=1, highlightbackground=ACCENT)
        self.hex_entry.pack(fill="x", pady=(2,0))

        self._refresh_key_ui()
        return f

    def _step_options(self):
        f = tk.Frame(self, bg=BG)
        c = card(f, "Additional options")

        tk.Checkbutton(c, text="Delete original file(s) after encryption",
                       variable=self.delete_original, bg=BG2, fg=FG,
                       selectcolor=BG3, activebackground=BG2, font=FONT).pack(anchor="w", pady=2)
        tk.Checkbutton(c, text="Zip folders into a single archive before encrypting  (--zip)",
                       variable=self.zip_folders, bg=BG2, fg=FG,
                       selectcolor=BG3, activebackground=BG2, font=FONT).pack(anchor="w", pady=2)

        tk.Frame(c, bg=BG2, height=10).pack()
        styled_label(c, "Output directory (optional):").pack(fill="x")
        od = tk.Frame(c, bg=BG2); od.pack(fill="x", pady=(4,0))
        tk.Entry(od, textvariable=self.out_dir_var, bg=BG3, fg=FG,
                 insertbackground=FG, relief="flat", font=FONT,
                 highlightthickness=1, highlightbackground=ACCENT).pack(side="left", fill="x", expand=True)
        styled_button(od, "Browse", self._browse_out, width=8).pack(side="left", padx=(6,0))
        return f

    def _step_run(self):
        f = tk.Frame(self, bg=BG)
        c = card(f, "Encrypt")
        self.enc_summary = tk.Label(c, text="", bg=BG2, fg=FG2, font=FONT_SM,
                                     justify="left", anchor="w", wraplength=460)
        self.enc_summary.pack(fill="x", pady=(0,10))
        self.enc_log = LogBox(c)
        self.enc_log.pack(fill="both", expand=True)
        tk.Frame(c, bg=BG2, height=8).pack()
        self.enc_btn = styled_button(c, "🔒  Encrypt Now", self._run_encrypt, width=20)
        self.enc_btn.pack()
        self.generated_key_var = tk.StringVar()
        self.key_result_frame = tk.Frame(c, bg=BG2)
        self.key_result_frame.pack(fill="x", pady=(8,0))
        return f

    # ── Nav buttons
    def _build_nav(self):
        nav = tk.Frame(self, bg=BG, pady=8)
        nav.pack(fill="x", side="bottom")
        self.back_btn = styled_button(nav, "← Back", self._back, color="#45475a", width=10)
        self.back_btn.pack(side="left", padx=12)
        self.next_btn = styled_button(nav, "Next →", self._next, width=10)
        self.next_btn.pack(side="right", padx=12)

    # ── Navigation
    def _show_step(self, n):
        for f in self.frames:
            f.pack_forget()
        self.frames[n].pack(fill="both", expand=True)
        self.step = n
        self._update_step_indicator()
        self.back_btn.config(state="normal" if n > 0 else "disabled")
        self.next_btn.config(text="Next →" if n < len(self.STEPS)-1 else "")
        self.next_btn.config(state="normal" if n < len(self.STEPS)-1 else "disabled")
        if n == len(self.STEPS) - 1:
            self._build_summary()

    def _next(self):
        if not self._validate_step():
            return
        self._show_step(self.step + 1)

    def _back(self):
        self._show_step(self.step - 1)

    # ── Validation
    def _validate_step(self):
        if self.step == 0:
            if not self.targets:
                messagebox.showwarning("No targets", "Please add at least one file or folder.")
                return False
        if self.step == 1:
            if self.key_mode.get() == "password":
                if not self.password_var.get():
                    messagebox.showwarning("No password", "Please enter a password.")
                    return False
                if self.password_var.get() != self.confirm_var.get():
                    messagebox.showerror("Mismatch", "Passwords do not match.")
                    return False
            else:
                if self.key_source.get() == "provide" and not self.hex_key_var.get().strip():
                    messagebox.showwarning("No key", "Please enter a hex key.")
                    return False
        return True

    # ── UI helpers
    def _refresh_key_ui(self):
        if self.key_mode.get() == "password":
            self.raw_frame.pack_forget()
            self.pw_frame.pack(fill="x")
        else:
            self.pw_frame.pack_forget()
            self.raw_frame.pack(fill="x")
            if self.key_source.get() == "provide":
                self.hex_label.pack(fill="x")
                self.hex_entry.pack(fill="x", pady=(2,0))
            else:
                self.hex_label.pack_forget()
                self.hex_entry.pack_forget()

    def _add_files(self):
        paths = filedialog.askopenfilenames(title="Select files")
        for p in paths:
            path = Path(p)
            if path not in self.targets:
                self.targets.append(path)
                self.target_listbox.insert("end", str(path))

    def _add_folder(self):
        p = filedialog.askdirectory(title="Select folder")
        if p:
            path = Path(p)
            if path not in self.targets:
                self.targets.append(path)
                self.target_listbox.insert("end", str(path))

    def _remove_target(self):
        sel = self.target_listbox.curselection()
        if sel:
            idx = sel[0]
            self.target_listbox.delete(idx)
            self.targets.pop(idx)

    def _browse_out(self):
        p = filedialog.askdirectory(title="Select output directory")
        if p:
            self.out_dir_var.set(p)

    def _build_summary(self):
        mode = "Password (PBKDF2)" if self.key_mode.get() == "password" else \
               f"Raw key ({'generate' if self.key_source.get() == 'generate' else 'provided'})"
        lines = [
            f"Targets     : {len(self.targets)} item(s)",
            f"Key mode    : {mode}",
            f"Key size    : AES-{self.key_bits.get()}",
            f"Zip folders : {'Yes' if self.zip_folders.get() else 'No'}",
            f"Delete orig : {'Yes' if self.delete_original.get() else 'No'}",
        ]
        if self.out_dir_var.get():
            lines.append(f"Output dir  : {self.out_dir_var.get()}")
        self.enc_summary.config(text="\n".join(lines))
        self.enc_log.clear()

    # ── Encryption runner
    def _run_encrypt(self):
        self.enc_btn.config(state="disabled", text="Encrypting…")
        self.enc_log.clear()
        threading.Thread(target=self._encrypt_thread, daemon=True).start()

    def _encrypt_thread(self):
        log = self.enc_log
        try:
            key_bits = int(self.key_bits.get())
            out_dir  = Path(self.out_dir_var.get()) if self.out_dir_var.get() else None

            # Build key
            if self.key_mode.get() == "password":
                import secrets as sec
                salt = sec.token_bytes(SALT_SIZE)
                key  = derive_key(self.password_var.get(), salt, key_bits)
                key_mode_int = 1
                log.write(f"  Key derived via PBKDF2-HMAC-SHA256 ({PBKDF2_ITER:,} iterations).", "info")
            else:
                salt = None
                if self.key_source.get() == "generate":
                    key = random_key(key_bits)
                    log.write(f"  Generated AES-{key_bits} key: {key.hex()}", "warn")
                    log.write("  *** Save this key – it cannot be recovered! ***", "warn")
                    self.generated_key_var.set(key.hex())
                    self._show_key_copy_button()
                else:
                    key = key_from_hex(self.hex_key_var.get().strip(), key_bits)
                    log.write(f"  Using provided AES-{key_bits} key.", "info")
                key_mode_int = 0

            # Process targets
            for target in self.targets:
                target = Path(target)
                if self.zip_folders.get() and target.is_dir():
                    log.write(f"  Zipping: {target} …", "info")
                    tmp_zip = zip_folder(target)
                    dst = (out_dir / (target.name + ".zip.enc")) if out_dir else \
                          target.parent / (target.name + ".zip.enc")
                    if out_dir:
                        out_dir.mkdir(parents=True, exist_ok=True)
                    encrypt_file(tmp_zip, dst, key, key_bits,
                                 salt if salt else bytes(SALT_SIZE), key_mode_int)
                    tmp_zip.unlink()
                    log.write(f"  Encrypted → {dst}", "ok")
                    if self.delete_original.get():
                        shutil.rmtree(target)
                        log.write(f"  Deleted original folder: {target}", "warn")
                else:
                    files = collect_files([str(target)])
                    for src in files:
                        dst = enc_output_path(src, out_dir)
                        encrypt_file(src, dst, key, key_bits,
                                     salt if salt else bytes(SALT_SIZE), key_mode_int)
                        log.write(f"  Encrypted: {src.name} → {dst.name}", "ok")
                        if self.delete_original.get():
                            src.unlink()
                            log.write(f"  Deleted: {src}", "warn")

            log.write("\n  ✓ All done!", "ok")

        except Exception as e:
            log.write(f"  ERROR: {e}", "err")
        finally:
            self.enc_btn.config(state="normal", text="🔒  Encrypt Now")

    def _show_key_copy_button(self):
        for w in self.key_result_frame.winfo_children():
            w.destroy()
        tk.Label(self.key_result_frame, text="Generated key (copy and save!):",
                 bg=BG2, fg=YELLOW, font=FONT_SM).pack(anchor="w")
        row = tk.Frame(self.key_result_frame, bg=BG2); row.pack(fill="x", pady=2)
        tk.Entry(row, textvariable=self.generated_key_var, bg=BG3, fg=YELLOW,
                 font=("Consolas", 8), relief="flat", state="readonly",
                 readonlybackground=BG3).pack(side="left", fill="x", expand=True)
        styled_button(row, "Copy", lambda: self._copy_key(), width=6,
                      color="#f9e2af").pack(side="left", padx=(4,0))

    def _copy_key(self):
        self.clipboard_clear()
        self.clipboard_append(self.generated_key_var.get())
        messagebox.showinfo("Copied", "Key copied to clipboard!")


# ══════════════════════════════════════════════════════════════════════════════
# DECRYPT WIZARD
# ══════════════════════════════════════════════════════════════════════════════

class DecryptWizard(tk.Frame):
    STEPS = ["1  Target", "2  Key", "3  Options", "4  Decrypt"]

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self.step = 0
        self.targets = []
        self.key_mode = tk.StringVar(value="password")
        self.password_var = tk.StringVar()
        self.hex_key_var = tk.StringVar()
        self.out_dir_var = tk.StringVar()

        self._build_header()
        self._build_steps()
        self._build_nav()
        self._show_step(0)

    def _build_header(self):
        hdr = tk.Frame(self, bg=BG, pady=10); hdr.pack(fill="x")
        self.step_labels = []
        for i, name in enumerate(self.STEPS):
            lbl = tk.Label(hdr, text=name, bg=BG, fg=FG2, font=FONT_SM, padx=8)
            lbl.pack(side="left")
            self.step_labels.append(lbl)
            if i < len(self.STEPS)-1:
                tk.Label(hdr, text="›", bg=BG, fg=FG2, font=FONT_SM).pack(side="left")

    def _update_step_indicator(self):
        for i, lbl in enumerate(self.step_labels):
            if i == self.step:
                lbl.config(fg=ACCENT2, font=FONT_BOLD)
            elif i < self.step:
                lbl.config(fg=GREEN, font=FONT_SM)
            else:
                lbl.config(fg=FG2, font=FONT_SM)

    def _build_steps(self):
        self.frames = [
            self._step_target(),
            self._step_key(),
            self._step_options(),
            self._step_run(),
        ]

    def _step_target(self):
        f = tk.Frame(self, bg=BG)
        c = card(f, "Select encrypted file(s) or folder to decrypt")
        self.target_listbox = tk.Listbox(c, bg=BG3, fg=FG, selectbackground=ACCENT,
                                          font=FONT, relief="flat", height=5,
                                          highlightthickness=1, highlightbackground=ACCENT)
        self.target_listbox.pack(fill="x", pady=(0,8))
        btns = tk.Frame(c, bg=BG2); btns.pack(fill="x")
        styled_button(btns, "＋ Add .enc File(s)", self._add_files, width=16).pack(side="left", padx=(0,6))
        styled_button(btns, "＋ Add Folder", self._add_folder, width=14).pack(side="left", padx=(0,6))
        styled_button(btns, "✕ Remove", self._remove_target, color="#e06c75", width=10).pack(side="left")
        return f

    def _step_key(self):
        f = tk.Frame(self, bg=BG)
        c = card(f, "Enter the key used to encrypt")
        styled_label(c, "Key Mode (must match encryption):").pack(fill="x")
        km = tk.Frame(c, bg=BG2); km.pack(fill="x", pady=(2,10))
        tk.Radiobutton(km, text="Password", variable=self.key_mode, value="password",
                       bg=BG2, fg=FG, selectcolor=BG3, activebackground=BG2, font=FONT,
                       command=self._refresh_key_ui).pack(anchor="w")
        tk.Radiobutton(km, text="Raw hex key", variable=self.key_mode, value="raw",
                       bg=BG2, fg=FG, selectcolor=BG3, activebackground=BG2, font=FONT,
                       command=self._refresh_key_ui).pack(anchor="w")

        self.pw_frame = tk.Frame(c, bg=BG2)
        styled_label(self.pw_frame, "Password:").pack(fill="x")
        tk.Entry(self.pw_frame, textvariable=self.password_var, show="●",
                 bg=BG3, fg=FG, insertbackground=FG, relief="flat", font=FONT,
                 highlightthickness=1, highlightbackground=ACCENT).pack(fill="x", pady=(2,0))

        self.raw_frame = tk.Frame(c, bg=BG2)
        styled_label(self.raw_frame, "Hex Key:").pack(fill="x")
        tk.Entry(self.raw_frame, textvariable=self.hex_key_var,
                 bg=BG3, fg=FG, insertbackground=FG, relief="flat",
                 font=("Consolas", 9),
                 highlightthickness=1, highlightbackground=ACCENT).pack(fill="x", pady=(2,0))

        self._refresh_key_ui()
        return f

    def _step_options(self):
        f = tk.Frame(self, bg=BG)
        c = card(f, "Output options")
        styled_label(c, "Output directory (optional — default: alongside .enc file):").pack(fill="x")
        od = tk.Frame(c, bg=BG2); od.pack(fill="x", pady=(4,0))
        tk.Entry(od, textvariable=self.out_dir_var, bg=BG3, fg=FG,
                 insertbackground=FG, relief="flat", font=FONT,
                 highlightthickness=1, highlightbackground=ACCENT).pack(side="left", fill="x", expand=True)
        styled_button(od, "Browse", self._browse_out, width=8).pack(side="left", padx=(6,0))
        return f

    def _step_run(self):
        f = tk.Frame(self, bg=BG)
        c = card(f, "Decrypt")
        self.dec_summary = tk.Label(c, text="", bg=BG2, fg=FG2, font=FONT_SM,
                                     justify="left", anchor="w", wraplength=460)
        self.dec_summary.pack(fill="x", pady=(0,10))
        self.dec_log = LogBox(c)
        self.dec_log.pack(fill="both", expand=True)
        tk.Frame(c, bg=BG2, height=8).pack()
        self.dec_btn = styled_button(c, "🔓  Decrypt Now", self._run_decrypt, width=20)
        self.dec_btn.pack()
        return f

    def _build_nav(self):
        nav = tk.Frame(self, bg=BG, pady=8); nav.pack(fill="x", side="bottom")
        self.back_btn = styled_button(nav, "← Back", self._back, color="#45475a", width=10)
        self.back_btn.pack(side="left", padx=12)
        self.next_btn = styled_button(nav, "Next →", self._next, width=10)
        self.next_btn.pack(side="right", padx=12)

    def _show_step(self, n):
        for f in self.frames: f.pack_forget()
        self.frames[n].pack(fill="both", expand=True)
        self.step = n
        self._update_step_indicator()
        self.back_btn.config(state="normal" if n > 0 else "disabled")
        self.next_btn.config(state="normal" if n < len(self.STEPS)-1 else "disabled")
        if n == len(self.STEPS)-1:
            self._build_summary()

    def _next(self):
        if not self._validate_step(): return
        self._show_step(self.step + 1)

    def _back(self):
        self._show_step(self.step - 1)

    def _validate_step(self):
        if self.step == 0 and not self.targets:
            messagebox.showwarning("No targets", "Please add at least one file or folder.")
            return False
        if self.step == 1:
            if self.key_mode.get() == "password" and not self.password_var.get():
                messagebox.showwarning("No password", "Please enter a password.")
                return False
            if self.key_mode.get() == "raw" and not self.hex_key_var.get().strip():
                messagebox.showwarning("No key", "Please enter a hex key.")
                return False
        return True

    def _refresh_key_ui(self):
        if self.key_mode.get() == "password":
            self.raw_frame.pack_forget()
            self.pw_frame.pack(fill="x")
        else:
            self.pw_frame.pack_forget()
            self.raw_frame.pack(fill="x")

    def _add_files(self):
        paths = filedialog.askopenfilenames(title="Select .enc files",
                                            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")])
        for p in paths:
            path = Path(p)
            if path not in self.targets:
                self.targets.append(path)
                self.target_listbox.insert("end", str(path))

    def _add_folder(self):
        p = filedialog.askdirectory(title="Select folder containing .enc files")
        if p:
            path = Path(p)
            if path not in self.targets:
                self.targets.append(path)
                self.target_listbox.insert("end", str(path))

    def _remove_target(self):
        sel = self.target_listbox.curselection()
        if sel:
            idx = sel[0]
            self.target_listbox.delete(idx)
            self.targets.pop(idx)

    def _browse_out(self):
        p = filedialog.askdirectory(title="Select output directory")
        if p: self.out_dir_var.set(p)

    def _build_summary(self):
        mode = "Password" if self.key_mode.get() == "password" else "Raw hex key"
        lines = [
            f"Targets  : {len(self.targets)} item(s)",
            f"Key mode : {mode}",
        ]
        if self.out_dir_var.get():
            lines.append(f"Output   : {self.out_dir_var.get()}")
        self.dec_summary.config(text="\n".join(lines))
        self.dec_log.clear()

    def _run_decrypt(self):
        self.dec_btn.config(state="disabled", text="Decrypting…")
        self.dec_log.clear()
        threading.Thread(target=self._decrypt_thread, daemon=True).start()

    def _decrypt_thread(self):
        log = self.dec_log
        try:
            password  = self.password_var.get() if self.key_mode.get() == "password" else None
            out_dir   = Path(self.out_dir_var.get()) if self.out_dir_var.get() else None

            for target in self.targets:
                target = Path(target)
                files  = collect_files([str(target)])
                enc_files = [f for f in files if f.suffix == ".enc"]

                if not enc_files:
                    log.write(f"  No .enc files found in {target}", "warn")
                    continue

                for src in enc_files:
                    raw_key = None
                    if self.key_mode.get() == "raw":
                        data = src.read_bytes()
                        key_bits, _, _ = _unpack_header(data)
                        raw_key = key_from_hex(self.hex_key_var.get().strip(), key_bits)

                    is_zip = src.stem.endswith(".zip")
                    if is_zip:
                        tmp_zip = Path(tempfile.mktemp(suffix=".zip"))
                        try:
                            decrypt_file(src, tmp_zip, password, raw_key)
                            dest_dir = out_dir if out_dir else src.parent
                            unzip_to(tmp_zip, dest_dir)
                            folder_name = src.name.replace(".zip.enc", "")
                            log.write(f"  Unzipped → {dest_dir / folder_name}", "ok")
                        except ValueError as e:
                            log.write(f"  ERROR: {e}", "err")
                        finally:
                            if tmp_zip.exists(): tmp_zip.unlink()
                    else:
                        dst = dec_output_path(src, out_dir)
                        try:
                            decrypt_file(src, dst, password, raw_key)
                            log.write(f"  Decrypted: {src.name} → {dst.name}", "ok")
                        except ValueError as e:
                            log.write(f"  ERROR: {e}", "err")

            log.write("\n  ✓ All done!", "ok")
        except Exception as e:
            log.write(f"  ERROR: {e}", "err")
        finally:
            self.dec_btn.config(state="normal", text="🔓  Decrypt Now")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN APP
# ══════════════════════════════════════════════════════════════════════════════

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AES Encryption Tool  |  CYBR 448")
        self.geometry("560x620")
        self.resizable(False, False)
        self.configure(bg=BG)
        self._build_ui()

    def _build_ui(self):
        # Title bar
        title_bar = tk.Frame(self, bg=ACCENT, pady=10)
        title_bar.pack(fill="x")
        tk.Label(title_bar, text="🔐  AES Data-at-Rest Encryption Tool",
                 bg=ACCENT, fg="white", font=("Segoe UI", 13, "bold")).pack(side="left", padx=16)
        tk.Label(title_bar, text="CYBR 448  •  AES-CBC  •  128/192/256-bit",
                 bg=ACCENT, fg="#ddd6fe", font=("Segoe UI", 9)).pack(side="right", padx=16)

        # Tab bar
        tab_bar = tk.Frame(self, bg=BG2, pady=0)
        tab_bar.pack(fill="x")
        self.tab_enc_btn = tk.Button(tab_bar, text="  🔒  Encrypt  ",
                                      bg=ACCENT, fg="white", relief="flat",
                                      font=FONT_BOLD, cursor="hand2", pady=8,
                                      command=lambda: self._switch_tab(0))
        self.tab_enc_btn.pack(side="left")
        self.tab_dec_btn = tk.Button(tab_bar, text="  🔓  Decrypt  ",
                                      bg=BG2, fg=FG2, relief="flat",
                                      font=FONT_BOLD, cursor="hand2", pady=8,
                                      command=lambda: self._switch_tab(1))
        self.tab_dec_btn.pack(side="left")

        # Content
        self.content = tk.Frame(self, bg=BG)
        self.content.pack(fill="both", expand=True)

        self.enc_tab = EncryptWizard(self.content)
        self.dec_tab = DecryptWizard(self.content)
        self._switch_tab(0)

    def _switch_tab(self, idx):
        self.enc_tab.pack_forget()
        self.dec_tab.pack_forget()
        if idx == 0:
            self.enc_tab.pack(fill="both", expand=True)
            self.tab_enc_btn.config(bg=ACCENT, fg="white")
            self.tab_dec_btn.config(bg=BG2, fg=FG2)
        else:
            self.dec_tab.pack(fill="both", expand=True)
            self.tab_dec_btn.config(bg=ACCENT, fg="white")
            self.tab_enc_btn.config(bg=BG2, fg=FG2)


if __name__ == "__main__":
    app = App()
    app.mainloop()
