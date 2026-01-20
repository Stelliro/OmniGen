import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog, Menu
import threading
import time
import os
import string
import datetime
import secrets
import base64
import ctypes
import platform
import math
import omni_core

# --- QUANTUM EDITOR ---
class QuantumEditor(tk.Toplevel):
    def __init__(self, parent, raw_data, on_save_callback):
        super().__init__(parent)
        self.title("QUANTUM TEXT EDITOR")
        self.geometry("900x700"); self.configure(bg="#050505")
        self.raw_data = raw_data; self.on_save = on_save_callback
        self.chunk_size = 5000 
        self.total_pages = math.ceil(len(raw_data) / self.chunk_size) if raw_data else 1
        self.current_page = 0
        self.setup_ui(); self.load_page(0)

    def setup_ui(self):
        tool = tk.Frame(self, bg="#111", height=40); tool.pack(fill="x", side="top")
        tk.Button(tool, text="<< PREV", command=self.prev_page, bg="#222", fg="#00FFC8", bd=0, font=("Consolas", 10)).pack(side="left", padx=5, pady=5)
        self.lbl_page = tk.Label(tool, text=f"SECTION 1 / {self.total_pages}", bg="#111", fg="white", font=("Consolas", 10)); self.lbl_page.pack(side="left", padx=10)
        tk.Button(tool, text="NEXT >>", command=self.next_page, bg="#222", fg="#00FFC8", bd=0, font=("Consolas", 10)).pack(side="left", padx=5, pady=5)
        tk.Label(tool, text="GOTO:", bg="#111", fg="#888").pack(side="left", padx=(20, 5))
        self.e_jump = tk.Entry(tool, width=5, bg="#333", fg="white", insertbackground="white"); self.e_jump.pack(side="left")
        self.e_jump.bind("<Return>", self.jump_page)
        tk.Button(tool, text="SAVE & CLOSE", command=self.save_exit, bg="#00FF41", fg="black", font=("Bold", 10)).pack(side="right", padx=10, pady=5)
        self.txt = tk.Text(self, bg="#0f0f0f", fg="#ccc", insertbackground="white", font=("Consolas", 11), undo=True)
        self.txt.pack(fill="both", expand=True, padx=10, pady=10)
        scroll = ttk.Scrollbar(self.txt, command=self.txt.yview); self.txt.configure(yscrollcommand=scroll.set); scroll.pack(side="right", fill="y")

    def save_current_chunk_to_memory(self):
        content = self.txt.get("1.0", "end-1c"); start = self.current_page * self.chunk_size
        pre = self.raw_data[:start]; old_end = min((self.current_page + 1) * self.chunk_size, len(self.raw_data)); post = self.raw_data[old_end:]
        self.raw_data = pre + content + post; self.total_pages = math.ceil(len(self.raw_data) / self.chunk_size) if self.raw_data else 1

    def load_page(self, page_num):
        if page_num != self.current_page: self.save_current_chunk_to_memory()
        self.current_page = page_num; start = page_num * self.chunk_size; end = start + self.chunk_size
        self.txt.delete("1.0", tk.END); self.txt.insert("1.0", self.raw_data[start:end])
        self.lbl_page.config(text=f"SECTION {self.current_page + 1} / {self.total_pages}")

    def prev_page(self): 
        if self.current_page > 0: self.load_page(self.current_page - 1)
    def next_page(self):
        if self.current_page < self.total_pages - 1: self.load_page(self.current_page + 1)
    def jump_page(self, event=None):
        try: 
            p = int(self.e_jump.get()) - 1
            if 0 <= p < self.total_pages: self.load_page(p)
        except: pass
    def save_exit(self): self.save_current_chunk_to_memory(); self.on_save(self.raw_data); self.destroy()

# --- CUSTOM WINDOW BASE ---
class AegisWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.overrideredirect(True)
        self.width = 1200; self.height = 950
        self.center_window(self.width, self.height)
        self.configure(bg="#050505")
        self.c_bg = "#050505"; self.c_panel = "#111111"; self.c_accent = "#00FFC8" 
        self.c_text = "#CCCCCC"; self.c_warn = "#FF3333"; self.c_success = "#00FF41"; self.c_select = "#004444"
        self.setup_styles(); self.setup_title_bar(); self.setup_status_bar(); self.setup_activity_monitor()

    def center_window(self, width, height):
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.geometry(f'{width}x{height}+{x}+{y}')

    def setup_styles(self):
        self.style = ttk.Style(); self.style.theme_use('clam')
        self.style.configure("Treeview", background=self.c_panel, foreground="white", fieldbackground=self.c_panel, font=("Segoe UI", 10), borderwidth=0)
        self.style.configure("Treeview.Heading", background="#1a1a1a", foreground=self.c_accent, font=("Consolas", 10, "bold"), borderwidth=1, relief="flat")
        self.style.map("Treeview", background=[('selected', self.c_select)], foreground=[('selected', 'white')])
        self.style.map("Treeview.Heading", background=[('active', '#222')])

    def setup_title_bar(self):
        self.title_bar = tk.Frame(self, bg="#151515", height=35)
        self.title_bar.pack(fill="x")
        self.title_bar.bind("<ButtonPress-1>", self.start_move)
        self.title_bar.bind("<B1-Motion>", self.do_move)
        tk.Label(self.title_bar, text=" OMNI-GEN: ZENITH (v24.2)", bg="#151515", fg=self.c_accent, font=("Impact", 12)).pack(side="left", padx=10)
        self.btn_lock = tk.Button(self.title_bar, text="LOCK SYSTEM", command=self.manual_lock, bg="#330000", fg="red", bd=0, font=("Bold", 9))
        self.btn_lock.pack(side="right", padx=5)
        tk.Button(self.title_bar, text=" X ", command=self.destroy, bg="#151515", fg="white", bd=0, activebackground="red").pack(side="right")

    def setup_status_bar(self):
        self.status_bar = tk.Label(self, text="READY", bg="#080808", fg="#555", anchor="w", font=("Consolas", 9), padx=10)
        self.status_bar.pack(side="bottom", fill="x")

    def set_status(self, msg, duration=3000):
        self.status_bar.config(text=msg, fg=self.c_accent)
        if duration: self.after(duration, lambda: self.status_bar.config(text="READY", fg="#555"))

    def start_move(self, event): self.x = event.x; self.y = event.y
    def do_move(self, event): self.geometry(f"+{self.winfo_pointerx()-self.x}+{self.winfo_pointery()-self.y}")

    def setup_activity_monitor(self):
        self.last_activity = time.time(); self.timeout_seconds = 300; self.keep_unlocked = False 
        self.bind_all("<Key>", self.reset_timer); self.bind_all("<Motion>", self.reset_timer)
        self.check_activity()

    def reset_timer(self, event=None): self.last_activity = time.time()
    def check_activity(self):
        if self.timeout_seconds > 0 and not self.keep_unlocked:
            if time.time() - self.last_activity > self.timeout_seconds: self.manual_lock()
        self.after(1000, self.check_activity)
    def manual_lock(self): pass

# --- MAIN APP ---
class OmniGenApp(AegisWindow):
    def __init__(self):
        super().__init__()
        self.core = omni_core.VaultManager()
        self.presets = omni_core.PresetManager()
        self.config = omni_core.ConfigManager()
        
        self.is_unlocked = False; self.generated_result = ""; self.stop_event = threading.Event()
        self.target_path = tk.StringVar(); self.fext = tk.StringVar(value=self.config.get("default_ext"))
        self.tsize = tk.StringVar(value="1"); self.tunit = tk.StringVar(value="GB")
        self.p_up = tk.BooleanVar(value=True); self.p_low = tk.BooleanVar(value=True)
        self.p_dig = tk.BooleanVar(value=True); self.p_sym = tk.BooleanVar(value=True)
        self.p_uni_math = tk.BooleanVar(value=True); self.p_uni_lang = tk.BooleanVar(value=False)
        self.p_uni_draw = tk.BooleanVar(value=False); self.p_cjk = tk.BooleanVar(value=False)
        self.p_emo = tk.BooleanVar(value=False); self.p_cust = tk.StringVar()
        self.excluded = set(); self.cur_pre = tk.StringVar()
        
        self.time_val = tk.StringVar(value=str(self.config.get("timeout_val")))
        self.time_unit = tk.StringVar(value=self.config.get("timeout_unit"))
        self.apply_timeout_settings() 
        
        self.v_search = tk.StringVar(); self.var_keep_open = tk.BooleanVar(value=False)
        self.setup_ui()

    def apply_timeout_settings(self):
        try:
            val = int(self.time_val.get()); u = self.time_unit.get()
            m = {"Seconds":1, "Minutes":60, "Hours":3600, "Days":86400, "Weeks":604800, 
                 "Months":2592000, "Years":31536000, "Decades":315360000, 
                 "Centuries":3153600000, "Millennia":31536000000}
            self.timeout_seconds = val * m.get(u, 60)
            self.config.set("timeout_val", val); self.config.set("timeout_unit", u)
        except: pass

    def setup_ui(self):
        self.tab_fr = tk.Frame(self, bg=self.c_bg); self.tab_fr.pack(fill="x", pady=5)
        self.mk_tab("GENERATOR", self.show_gen); self.mk_tab("DECODER", self.show_dec)
        self.mk_tab("VAULT", self.show_vault); self.mk_tab("SETTINGS", self.show_settings)
        self.content = tk.Frame(self, bg=self.c_bg); self.content.pack(fill="both", expand=True, padx=20, pady=10)
        self.show_gen()

    def mk_tab(self, txt, cmd):
        tk.Button(self.tab_fr, text=txt, command=cmd, bg=self.c_panel, fg=self.c_text, bd=0, font=("Segoe UI", 11, "bold"), width=15).pack(side="left", padx=2)

    def manual_lock(self):
        self.is_unlocked = False; self.keep_unlocked = False; self.var_keep_open.set(False); self.show_vault()
        self.set_status("SYSTEM LOCKED")

    def copy_to_clipboard_secure(self, text):
        self.clipboard_clear(); self.clipboard_append(text)
        self.set_status("COPIED TO CLIPBOARD (SECURE ERASE IN 30s)")
        self.after(30000, lambda: [self.clipboard_clear(), self.set_status("CLIPBOARD CLEARED")])

    # --- POPUPS ---
    def popup_io_menu(self):
        top = tk.Toplevel(self); top.geometry("300x250"); top.configure(bg="#222"); top.title("INTEROPERABILITY")
        tk.Label(top, text="DATA TRANSFER", bg="#222", fg=self.c_accent, font=("Impact", 12)).pack(pady=10)
        def do_export_csv():
            if messagebox.askyesno("Warning", "Exporting to CSV will save passwords in PLAIN TEXT.\nAre you sure?"):
                f = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
                if f: self.core.export_csv(f); self.set_status("VAULT EXPORTED TO CSV"); top.destroy()
        def do_import_csv():
            f = filedialog.askopenfilename(filetypes=[("CSV", "*.csv")])
            if f:
                try: count = self.core.import_csv(f); self.refresh_vault(); self.set_status(f"IMPORTED {count} ENTRIES"); top.destroy()
                except Exception as e: messagebox.showerror("Error", str(e))
        tk.Button(top, text="EXPORT TO CSV (UNSAFE)", command=do_export_csv, bg=self.c_warn, fg="black").pack(fill="x", padx=20, pady=5)
        tk.Button(top, text="IMPORT FROM CSV", command=do_import_csv, bg=self.c_success, fg="black").pack(fill="x", padx=20, pady=5)
        tk.Button(top, text="CANCEL", command=top.destroy, bg="#444", fg="white").pack(fill="x", padx=20, pady=20)

    # --- VAULT LOGIC ---
    def show_vault(self):
        self.clr()
        if not self.core.is_setup(): self.vault_setup(); return
        if not self.is_unlocked: self.vault_login(); return
        
        top = tk.Frame(self.content, bg=self.c_bg); top.pack(fill="x", pady=5)
        def toggle_keep():
            self.keep_unlocked = self.var_keep_open.get()
            s = "DISABLED" if not self.keep_unlocked else "ACTIVE"
            color = self.c_warn if not self.keep_unlocked else self.c_success
            self.lbl_stat.config(text=f"TIMEOUT: {s}", fg=color)
        chk = tk.Checkbutton(top, text="KEEP UNLOCKED", variable=self.var_keep_open, command=toggle_keep, 
                             bg=self.c_bg, fg="white", selectcolor="#222", activebackground=self.c_bg)
        chk.pack(side="left")
        self.lbl_stat = tk.Label(top, text="TIMEOUT: ACTIVE", bg=self.c_bg, fg=self.c_warn, font=("Consolas", 8))
        self.lbl_stat.pack(side="left", padx=5)
        if self.keep_unlocked: self.var_keep_open.set(True); self.lbl_stat.config(text="TIMEOUT: DISABLED", fg=self.c_success)

        tk.Button(top, text="I/O", command=self.popup_io_menu, bg="#444", fg="white", font=("Bold", 9)).pack(side="right", padx=5)
        tk.Button(top, text="ADD ENTRY", command=lambda: self.popup_add_entry(False), bg=self.c_success, fg="black").pack(side="right")
        tk.Entry(top, textvariable=self.v_search, bg="#222", fg="white", width=30).pack(side="right", padx=10)
        tk.Label(top, text="SEARCH:", bg=self.c_bg, fg="white").pack(side="right")
        self.v_search.trace("w", self.refresh_vault)

        cols = ("ID", "Label", "User", "Pass"); self.tree = ttk.Treeview(self.content, columns=cols, show="headings")
        self.tree.heading("ID", text="ID"); self.tree.column("ID", width=30)
        self.tree.heading("Label", text="Label"); self.tree.heading("User", text="User"); self.tree.heading("Pass", text="Password")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Button-1>", self.on_drag_start); self.tree.bind("<B1-Motion>", self.on_drag_motion); self.tree.bind("<ButtonRelease-1>", self.on_drag_release)
        self.tree.bind("<Button-3>", self.show_context_menu)
        bot = tk.Frame(self.content, bg=self.c_bg); bot.pack(fill="x", pady=5)
        tk.Button(bot, text="DETAILS", command=self.vault_detail, bg=self.c_accent, fg="black").pack(side="left", fill="x", expand=True)
        self.refresh_vault()

    def on_drag_start(self, event):
        item = self.tree.identify_row(event.y); 
        if item: self.drag_item = item
    def on_drag_motion(self, event): pass
    def on_drag_release(self, event):
        if not hasattr(self, 'drag_item') or not self.drag_item: return
        target = self.tree.identify_row(event.y)
        if target and target != self.drag_item: self.tree.move(self.drag_item, "", self.tree.index(target))
        self.drag_item = None

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if not item: return
        self.tree.selection_set(item)
        m = Menu(self, tearoff=0, bg="#222", fg="white")
        m.add_command(label="Edit Entry", command=self.vault_edit)
        m.add_separator()
        m.add_command(label="Copy Password", command=self.copy_vault_pass)
        m.add_command(label="Copy Username", command=self.copy_vault_user)
        m.add_separator()
        m.add_command(label="Delete", command=self.vault_del)
        m.post(event.x_root, event.y_root)

    def vault_edit(self):
        s = self.tree.selection()
        if not s: return
        eid = s[0]; row = self.core.get_full_decrypted_entry(eid)
        if not row: return
        top = tk.Toplevel(self); top.geometry("500x650"); top.configure(bg="#222"); top.title("EDIT ENTRY")
        style = {"bg": "#333", "fg": "white", "relief": "flat"}
        def fld(txt, val): 
            tk.Label(top, text=txt, bg="#222", fg="white").pack(anchor="w", padx=20, pady=(10,0))
            e = tk.Entry(top, **style); e.pack(fill="x", padx=20); e.insert(0, val); return e
        e_lbl = fld("LABEL:", row[1]); e_usr = fld("USER:", row[2]); e_url = fld("URL:", row[5])
        tk.Label(top, text="PASSWORD:", bg="#222", fg="white").pack(anchor="w", padx=20, pady=(10,0))
        p_frame = tk.Frame(top, bg="#222"); p_frame.pack(fill="x", padx=20)
        raw_pass = row[4]; preview_text = raw_pass[:20] + "..." if len(raw_pass) > 20 else raw_pass
        lbl_preview = tk.Label(p_frame, text=preview_text, bg="#333", fg="#00FFC8", font=("Consolas", 10), width=30, anchor="w"); lbl_preview.pack(side="left", fill="x", expand=True)
        def cp(): self.copy_to_clipboard_secure(self.temp_pass_holder)
        def open_editor():
            def on_save_pw(new_data):
                self.temp_pass_holder = new_data; p_len = len(new_data)
                prev = new_data[:20] + "..." if p_len > 20 else new_data; lbl_preview.config(text=f"{prev} ({p_len} chars)")
            QuantumEditor(top, self.temp_pass_holder, on_save_pw)
        self.temp_pass_holder = raw_pass
        tk.Button(p_frame, text="COPY", command=cp, bg="#444", fg="white", bd=0).pack(side="left", padx=2)
        tk.Button(p_frame, text="EDITOR", command=open_editor, bg=self.c_accent, fg="black", bd=0, font=("Bold", 8)).pack(side="left", padx=2)
        tk.Label(top, text="NOTES:", bg="#222", fg="white").pack(anchor="w", padx=20, pady=(10,0))
        e_not = tk.Text(top, height=5, **style); e_not.pack(fill="x", padx=20); e_not.insert("1.0", row[6])
        def save():
            self.core.update_entry(eid, e_lbl.get(), e_usr.get(), "", self.temp_pass_holder, e_url.get(), e_not.get("1.0", tk.END))
            self.refresh_vault(); top.destroy(); self.set_status("ENTRY UPDATED")
        tk.Button(top, text="UPDATE ENTRY", command=save, bg=self.c_success, fg="black", font=("Bold", 10)).pack(fill="x", padx=20, pady=20)

    def copy_vault_user(self): self.copy_col(2)
    def copy_vault_pass(self): self.copy_col(4)
    def copy_col(self, idx):
        s = self.tree.selection()
        if s: 
            r = self.core.get_full_decrypted_entry(s[0])
            if r: self.copy_to_clipboard_secure(r[idx])

    def vault_login(self):
        f = self.mk_frame(" LOCKED "); f.pack(expand=True)
        tk.Label(f, text="PIN", bg=self.c_bg, fg="white").pack()
        e1 = tk.Entry(f, show="#", font=("Consolas", 16), justify='center'); e1.pack(pady=5)
        tk.Label(f, text="2FA CODE", bg=self.c_bg, fg="white").pack()
        e2 = tk.Entry(f, font=("Consolas", 16), justify='center'); e2.pack(pady=5)
        def check():
            ok, msg = self.core.verify_credentials(e1.get(), e2.get())
            if ok: self.is_unlocked = True; self.show_vault(); self.set_status("VAULT DECRYPTED")
            else: messagebox.showerror("Denied", msg)
        tk.Button(f, text="UNLOCK", command=check, bg=self.c_accent, fg="black").pack(pady=20)
        def factory_reset():
            if messagebox.askyesno("DANGER", "Wipe all data?"):
                if self.core.factory_reset(): messagebox.showinfo("Reset", "Vault Wiped."); self.show_vault()
        tk.Button(f, text="RESET VAULT", command=factory_reset, bg=self.c_warn, fg="black").pack(pady=20)

    def vault_setup(self):
        f = self.mk_frame(" INITIAL SETUP ")
        tk.Label(f, text="CREATE 4-DIGIT PIN", bg=self.c_bg, fg="white").pack()
        self.e_pin = tk.Entry(f, show="#", font=("Consolas", 20), justify='center'); self.e_pin.pack(pady=5)
        sec = base64.b32encode(secrets.token_bytes(10)).decode()
        tk.Label(f, text=f"ADD TO AUTHENTICATOR:\n{sec}", bg=self.c_bg, fg="yellow").pack(pady=10)
        tk.Label(f, text="VERIFY CODE:", bg=self.c_bg, fg="white").pack()
        e_ver = tk.Entry(f, font=("Consolas", 16), justify='center'); e_ver.pack(pady=5)
        def save():
            if len(self.e_pin.get()) < 4: return
            t = omni_core.IroncladCrypto.get_totp_token(sec)
            try:
                if int(e_ver.get()) != t: messagebox.showerror("Error", "2FA Failed"); return
            except: return
            self.core.set_security(self.e_pin.get(), sec); self.show_vault(); self.set_status("VAULT ENCRYPTED")
        tk.Button(f, text="VERIFY & LOCK", command=save, bg=self.c_success, fg="black").pack(pady=20)

    def popup_add_entry(self, use_generated=False):
        top = tk.Toplevel(self); top.geometry("400x500"); top.configure(bg="#222")
        def field(txt): tk.Label(top, text=txt, bg="#222", fg="white").pack(anchor="w", padx=20)
        style = {"bg": "#333", "fg": "white", "relief": "flat"}
        field("LABEL:"); e_lbl = tk.Entry(top, **style); e_lbl.pack(fill="x", padx=20)
        field("USER/EMAIL:"); e_usr = tk.Entry(top, **style); e_usr.pack(fill="x", padx=20)
        field("URL:"); e_url = tk.Entry(top, **style); e_url.pack(fill="x", padx=20)
        field("PASSWORD:"); e_pas = tk.Entry(top, **style); e_pas.pack(fill="x", padx=20)
        if use_generated and self.generated_result: e_pas.insert(0, self.generated_result)
        field("NOTES:"); e_not = tk.Text(top, height=5, **style); e_not.pack(fill="x", padx=20)
        def save():
            if not e_lbl.get(): return
            self.core.add_entry(e_lbl.get(), e_usr.get(), "", e_pas.get(), e_url.get(), e_not.get("1.0", tk.END))
            if self.is_unlocked: self.refresh_vault() 
            top.destroy(); self.set_status("ENTRY SAVED")
        tk.Button(top, text="SAVE", command=save, bg=self.c_success, fg="black", font=("Bold", 10)).pack(fill="x", padx=20, pady=20)

    def refresh_vault(self, *a):
        try:
            for i in self.tree.get_children(): self.tree.delete(i)
            for r in self.core.get_entries(self.v_search.get()):
                self.tree.insert("", "end", iid=r[0], values=(r[0], r[1], r[2], "••••••"))
        except: pass

    def vault_del(self):
        s = self.tree.selection()
        if s: self.core.delete_entry(s[0]); self.refresh_vault(); self.set_status("ENTRY DELETED")

    def vault_detail(self):
        s = self.tree.selection()
        if not s: return
        r = self.core.get_full_decrypted_entry(s[0])
        if r: 
            top = tk.Toplevel(self); top.geometry("400x300"); top.configure(bg="#222"); top.title("DETAILS")
            def show_row(txt, val):
                f = tk.Frame(top, bg="#222"); f.pack(fill="x", padx=20, pady=5)
                tk.Label(f, text=txt, bg="#222", fg="#00FFC8", width=10, anchor="w").pack(side="left")
                tk.Label(f, text=val if txt!="PASS:" else "******", bg="#222", fg="white").pack(side="left")
                tk.Button(f, text="COPY", bg="#444", fg="white", bd=0, command=lambda: self.copy_to_clipboard_secure(val)).pack(side="right")
            show_row("LABEL:", r[1]); show_row("USER:", r[2]); show_row("URL:", r[5]); show_row("PASS:", r[4])
            tk.Label(top, text="NOTES:", bg="#222", fg="#00FFC8").pack(anchor="w", padx=20, pady=(10,0))
            tk.Label(top, text=r[6], bg="#222", fg="white", wraplength=350).pack(anchor="w", padx=20)

    # --- DECODER TAB (MODIFIED) ---
    def show_dec(self):
        self.clr()
        # Ensure the decoder UI fills the entire available area
        f = tk.LabelFrame(self.content, text=" DECODER ", bg=self.c_bg, fg=self.c_accent, font=("Consolas", 11))
        # Use expand=True so it claims vertical space
        f.pack(fill="both", expand=True, pady=10)
        
        tk.Button(f, text="OPEN FILE", command=self.run_decode, bg=self.c_accent, fg="black").pack(pady=10)
        
        # Remove fixed height to let text box expand to bottom
        self.txt_dec = tk.Text(f, bg="black", fg=self.c_success, bd=0)
        self.txt_dec.pack(fill="both", expand=True, padx=10, pady=10)

    def run_decode(self):
        p = filedialog.askopenfilename(filetypes=[("Omni", "*.omni")])
        if not p: return
        self.txt_dec.delete("1.0", tk.END)
        try:
            for chunk in omni_core.OmniFileHandler.read_omni(p): self.txt_dec.insert(tk.END, chunk)
            self.set_status("DECODING COMPLETE")
        except: self.set_status("DECODE ERROR")

    def show_settings(self):
        self.clr(); f = self.mk_frame(" CONFIG ")
        tk.Label(f, text="AUTO-LOGOUT:", bg=self.c_bg, fg="white").pack(anchor="w", padx=10)
        r = tk.Frame(f, bg=self.c_bg); r.pack(fill="x", padx=10)
        tk.Entry(r, textvariable=self.time_val, width=10).pack(side="left")
        units = ["Seconds", "Minutes", "Hours", "Days", "Weeks", "Months", "Years", "Decades", "Centuries", "Millennia"]
        tk.OptionMenu(r, self.time_unit, *units).pack(side="left")
        def apply():
            try:
                v = int(self.time_val.get()); u = self.time_unit.get()
                m = {"Seconds":1, "Minutes":60, "Hours":3600, "Days":86400, "Weeks":604800, 
                     "Months":2592000, "Years":31536000, "Decades":315360000, 
                     "Centuries":3153600000, "Millennia":31536000000}
                self.timeout_seconds = v * m.get(u, 60)
                self.config.set("timeout_val", v); self.config.set("timeout_unit", u)
                messagebox.showinfo("Applied", f"Timeout set to {v} {u}")
            except: pass
        tk.Button(r, text="APPLY", command=apply, bg=self.c_accent, fg="black").pack(side="left")
        
        f2 = self.mk_frame(" SECURITY ROTATION ")
        tk.Label(f2, text="CHANGE MASTER CREDENTIALS", bg=self.c_bg, fg="#FF9900").pack(anchor="w", padx=10, pady=5)
        def do_rotate():
            if not self.is_unlocked: messagebox.showerror("Locked", "Must be logged in."); return
            top = tk.Toplevel(self); top.geometry("400x400"); top.configure(bg="#222"); top.title("ROTATE KEYS")
            tk.Label(top, text="NEW PIN:", bg="#222", fg="white").pack(pady=5); e_p = tk.Entry(top, show="#", font=("Consolas", 14), justify="center"); e_p.pack()
            sec = base64.b32encode(secrets.token_bytes(10)).decode(); tk.Label(top, text=f"NEW 2FA SECRET:\n{sec}", bg="#222", fg="yellow").pack(pady=10)
            tk.Label(top, text="VERIFY 2FA CODE:", bg="#222", fg="white").pack(pady=5); e_c = tk.Entry(top, font=("Consolas", 14), justify="center"); e_c.pack()
            def commit_rot():
                if len(e_p.get()) < 4: return
                t = omni_core.IroncladCrypto.get_totp_token(sec)
                try: 
                    if int(e_c.get()) != t: messagebox.showerror("Error", "2FA Mismatch"); return
                except: return
                ok, msg = self.core.change_credentials(e_p.get(), sec)
                if ok: messagebox.showinfo("Success", "Credentials Updated."); top.destroy()
                else: messagebox.showerror("Error", msg)
            tk.Button(top, text="RE-ENCRYPT VAULT", command=commit_rot, bg="red", fg="white").pack(pady=20)
        tk.Button(f2, text="CHANGE PIN & 2FA", command=do_rotate, bg="#333", fg="white").pack(fill="x", padx=20, pady=5)
        
        c = self.mk_frame(" SYSTEM PREFERENCES ")
        tk.Label(c, text="DEFAULT FORMAT:", bg=self.c_bg, fg="white").pack(anchor="w", padx=10, pady=(10,0))
        def set_fmt(v): self.config.set("default_ext", v); self.fext.set(v)
        fr = tk.Frame(c, bg=self.c_bg); fr.pack(fill="x", padx=10)
        tk.Button(fr, text=".omni", command=lambda: set_fmt(".omni"), bg="#333", fg="white").pack(side="left")
        tk.Button(fr, text=".txt", command=lambda: set_fmt(".txt"), bg="#333", fg="white").pack(side="left", padx=5)

        d = self.mk_frame(" DATA MANAGEMENT ")
        tk.Button(d, text="CLEAR CLIPBOARD NOW", command=self.clipboard_clear, bg="#444", fg="white").pack(fill="x", padx=20, pady=5)

    # --- GENERATOR TAB ---
    def show_gen(self):
        self.clr()
        hw = self.mk_frame(" 1. TARGET VECTOR ")
        d_row = tk.Frame(hw, bg=self.c_bg); d_row.pack(fill="x", pady=10, padx=10)
        tk.Label(d_row, text="PATH (Optional):", bg=self.c_bg, fg="white").pack(side="left")
        e_path = tk.Entry(d_row, textvariable=self.target_path, bg="#222", fg=self.c_accent, font=("Consolas", 10))
        e_path.pack(side="left", fill="x", expand=True, padx=10)
        tk.Button(d_row, text="BROWSE...", command=self.browse_file, bg="#333", fg="white").pack(side="left", padx=2)
        tk.Label(d_row, text=" | FORMAT:", bg=self.c_bg, fg="gray").pack(side="left", padx=5)
        tk.Radiobutton(d_row, text=".omni", variable=self.fext, value=".omni", bg=self.c_bg, fg="white", selectcolor="#333").pack(side="left")
        tk.Radiobutton(d_row, text=".txt", variable=self.fext, value=".txt", bg=self.c_bg, fg="white", selectcolor="#333").pack(side="left")

        mx = self.mk_frame(" 2. ENTROPY MATRIX ")
        r1 = tk.Frame(mx, bg=self.c_bg); r1.pack(fill="x", padx=10)
        self.mk_chk(r1, "A-Z", self.p_up); self.mk_chk(r1, "a-z", self.p_low); self.mk_chk(r1, "0-9", self.p_dig); self.mk_chk(r1, "Sym", self.p_sym)
        r2 = tk.Frame(mx, bg=self.c_bg); r2.pack(fill="x", padx=10, pady=5)
        self.mk_chk(r2, "Math", self.p_uni_math); self.mk_chk(r2, "Lang", self.p_uni_lang); 
        self.mk_chk(r2, "Box", self.p_uni_draw); self.mk_chk(r2, "CJK", self.p_cjk); self.mk_chk(r2, "Emoji", self.p_emo)
        crow = tk.Frame(mx, bg=self.c_bg); crow.pack(fill="x", pady=10, padx=10)
        tk.Entry(crow, textvariable=self.p_cust, bg="#222", fg="white").pack(side="left", fill="x", expand=True, padx=5)
        tk.Button(crow, text="EDITOR", command=self.open_matrix, bg="#333", fg="white").pack(side="left")

        ac = tk.Frame(self.content, bg=self.c_bg); ac.pack(fill="x", pady=10)
        tk.Entry(ac, textvariable=self.tsize, width=8, font=("Consolas", 14)).pack(side="left")
        units = ["Characters", "Bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
        tk.OptionMenu(ac, self.tunit, *units).pack(side="left")
        self.btn_go = tk.Button(ac, text="INITIALIZE", command=self.run_gen, bg=self.c_accent, fg="black", font=("Impact", 14), width=20)
        self.btn_go.pack(side="left", padx=20)
        self.prog = ttk.Progressbar(self.content, mode='determinate'); self.prog.pack(fill="x")

        pr = tk.Frame(self.content, bg=self.c_bg); pr.pack(fill="x", pady=10)
        tk.Label(pr, text="PROFILE:", bg=self.c_bg, fg="white").pack(side="left")
        self.cb_pre = ttk.Combobox(pr, textvariable=self.cur_pre, values=list(self.presets.data.keys()), width=15); self.cb_pre.pack(side="left")
        tk.Button(pr, text="LOAD", command=lambda: self.load_pre(None), bg="#333", fg="white").pack(side="left", padx=2)
        tk.Button(pr, text="SAVE", command=self.save_pre, bg="#333", fg="white").pack(side="left", padx=2)
        self.btn_export = tk.Button(pr, text="EXPORT FILE", command=self.export_file, bg=self.c_panel, fg="gray", state="disabled")
        self.btn_export.pack(side="right", padx=5)
        self.btn_add_vault = tk.Button(pr, text="ADD TO VAULT", command=self.request_vault_save, bg=self.c_panel, fg="gray", state="disabled")
        self.btn_add_vault.pack(side="right", padx=5)

    def browse_file(self):
        ext = self.fext.get()
        f = filedialog.asksaveasfilename(defaultextension=ext, filetypes=[(f"{ext} File", f"*{ext}")])
        if f: self.target_path.set(f)

    def run_gen(self):
        try:
            val = float(self.tsize.get()); u = self.tunit.get()
            if u == "Characters": target = int(val); is_char = True
            else:
                p_map = {"Bytes":1, "KB":1024, "MB":1024**2, "GB":1024**3, "TB":1024**4, "PB":1024**5, "EB":1024**6, "ZB":1024**7, "YB":1024**8}
                target = int(val * p_map.get(u, 1)); is_char = False
        except: return

        pool = ""
        if self.p_up.get(): pool += string.ascii_uppercase
        if self.p_low.get(): pool += string.ascii_lowercase
        if self.p_dig.get(): pool += string.digits
        if self.p_sym.get(): pool += string.punctuation
        if self.p_uni_math.get(): pool += "".join(chr(c) for c in range(0x2190, 0x2400))
        if self.p_uni_lang.get(): pool += "".join(chr(c) for c in range(0x00A1, 0x0500))
        if self.p_uni_draw.get(): pool += "".join(chr(c) for c in range(0x2500, 0x2600))
        if self.p_cjk.get(): pool += "".join(chr(c) for c in range(0x4E00, 0x51E0)) 
        if self.p_emo.get(): pool += "".join(chr(c) for c in range(0x1F600, 0x1F650))
        pool += self.p_cust.get()
        final_pool = [c for c in pool if c not in self.excluded]
        if not final_pool: messagebox.showerror("Err", "Pool Empty"); return

        path = self.target_path.get()
        if target > 50 * 1024 * 1024 and not path:
            messagebox.showinfo("Size Alert", "Large file must stream to disk."); self.browse_file(); path = self.target_path.get()
            if not path: return

        self.btn_go.config(state="disabled"); self.stop_event.clear(); self.set_status("GENERATING...")
        threading.Thread(target=self.worker, args=(path, target, final_pool, is_char)).start()

    def worker(self, path, size, pool, is_char):
        def cb(w): self.prog['value'] = (w/size)*100
        try:
            if path:
                omni_core.OmniFileHandler.write_stream(path, size, pool, cb, self.stop_event, is_char)
                self.generated_result = "FILE_ON_DISK"
                if size < 50000 and not path.endswith(".omni"):
                    try: 
                        with open(path, "r", encoding="utf-8") as f: self.generated_result = f.read()
                    except: pass
                self.set_status("STREAM COMPLETE")
                messagebox.showinfo("Success", f"Data Streamed to:\n{path}")
            else:
                raw_chars = [secrets.choice(pool) for _ in range(size)]
                self.generated_result = "".join(raw_chars)
                cb(size)
                self.set_status("GENERATION COMPLETE")
                messagebox.showinfo("Success", "Generated to Memory.")

            if self.generated_result != "FILE_ON_DISK":
                self.btn_add_vault.config(state="normal", fg="white", bg=self.c_success)
                self.btn_export.config(state="normal", fg="white", bg=self.c_accent)
            else:
                self.btn_add_vault.config(state="disabled", bg=self.c_panel)
                self.btn_export.config(state="disabled", bg=self.c_panel)
        except Exception as e: messagebox.showerror("Error", str(e))
        finally: self.btn_go.config(state="normal")

    def export_file(self):
        if not self.generated_result or self.generated_result == "FILE_ON_DISK": return
        ext = self.fext.get()
        f = filedialog.asksaveasfilename(defaultextension=ext, filetypes=[(f"{ext} File", f"*{ext}")])
        if f:
            try:
                if f.endswith(".omni"):
                    import zlib
                    with open(f, "wb") as file_obj:
                        file_obj.write(b'OMNI_V15')
                        data = zlib.compress(self.generated_result.encode())
                        file_obj.write(len(data).to_bytes(4, 'big')); file_obj.write(data)
                else:
                    with open(f, "w", encoding="utf-8") as file_obj: file_obj.write(self.generated_result)
                self.set_status("FILE EXPORTED")
            except Exception as e: messagebox.showerror("Error", str(e))

    def request_vault_save(self):
        if not self.generated_result or self.generated_result == "FILE_ON_DISK": return
        if self.is_unlocked: self.popup_add_entry(use_generated=True)
        else: self.popup_sentinel_login()

    def popup_sentinel_login(self):
        top = tk.Toplevel(self); top.geometry("400x300"); top.configure(bg=self.c_panel)
        top.title("SENTINEL INTERCEPT")
        tk.Label(top, text="SECURITY CLEARANCE REQUIRED", bg=self.c_panel, fg=self.c_warn, font=("Impact", 14)).pack(pady=20)
        tk.Label(top, text="PIN:", bg=self.c_panel, fg="white").pack()
        e_pin = tk.Entry(top, show="*", justify='center', bg="#222", fg="white", font=("Consolas", 12)); e_pin.pack(pady=5); e_pin.focus()
        tk.Label(top, text="2FA CODE:", bg=self.c_panel, fg="white").pack()
        e_2fa = tk.Entry(top, justify='center', bg="#222", fg="white", font=("Consolas", 12)); e_2fa.pack(pady=5)
        def attempt():
            ok, msg = self.core.verify_credentials(e_pin.get(), e_2fa.get())
            if ok: self.is_unlocked = True; top.destroy(); self.popup_add_entry(use_generated=True)
            else: messagebox.showerror("Denied", "Invalid Credentials"); e_pin.delete(0, tk.END)
        tk.Button(top, text="AUTHENTICATE", command=attempt, bg=self.c_accent, fg="black").pack(pady=20)

    def clr(self): 
        for w in self.content.winfo_children(): w.destroy()
    def mk_frame(self, txt): 
        f = tk.LabelFrame(self.content, text=txt, bg=self.c_bg, fg=self.c_accent, font=("Consolas", 11)); f.pack(fill="x", pady=10); return f
    def mk_chk(self, p, t, v): 
        tk.Checkbutton(p, text=t, variable=v, bg=self.c_bg, fg="white", selectcolor="#222").pack(side="left", padx=10)
    
    def open_matrix(self): 
        base = self.get_pool_base()
        if not base: return
        top = tk.Toplevel(self); top.geometry("1000x700"); top.configure(bg="#111")
        f = ttk.Frame(top); f.pack(fill="both", expand=True)
        sf = ScrollableFrame(f); sf.pack(fill="both", expand=True) 
        inner = sf.scrollable_window
        self.mat_vars = {}
        r=0; c=0; max_c=18
        limit=5000; shown_base=base[:limit]
        for char in shown_base:
            v = tk.BooleanVar(value=char not in self.excluded)
            self.mat_vars[char] = v
            txt = char if char != " " else "SPC"
            tk.Checkbutton(inner, text=txt, variable=v, bg="#111", fg="#0ff", selectcolor="#333", font=("Arial", 10)).grid(row=r, column=c)
            c+=1
            if c>max_c: c=0; r+=1
        def save():
            self.excluded = {ch for ch, var in self.mat_vars.items() if not var.get()}
            top.destroy()
        btn = ttk.Frame(top); btn.pack(fill="x")
        tk.Button(btn, text="SAVE", command=save, bg="#0f0", fg="black").pack(fill="x", pady=5)

    def get_pool_base(self):
        pool = ""
        if self.p_up.get(): pool += string.ascii_uppercase
        if self.p_low.get(): pool += string.ascii_lowercase
        if self.p_dig.get(): pool += string.digits
        if self.p_sym.get(): pool += string.punctuation
        if self.p_uni_math.get(): pool += "".join(chr(c) for c in range(0x2190, 0x2400))
        if self.p_uni_lang.get(): pool += "".join(chr(c) for c in range(0x00A1, 0x0500))
        if self.p_uni_draw.get(): pool += "".join(chr(c) for c in range(0x2500, 0x2600))
        if self.p_cjk.get(): pool += "".join(chr(c) for c in range(0x4E00, 0x51E0)) 
        if self.p_emo.get(): pool += "".join(chr(c) for c in range(0x1F600, 0x1F650))
        pool += self.p_cust.get()
        return sorted(list(set(pool)))

    def save_pre(self): 
        n = simpledialog.askstring("Save", "Name:"); 
        if n: 
            d = {"upper": self.p_up.get(), "lower": self.p_low.get(), "dig": self.p_dig.get(), "sym": self.p_sym.get(),
                 "math": self.p_uni_math.get(), "lang": self.p_uni_lang.get(), "box": self.p_uni_draw.get(), 
                 "cjk": self.p_cjk.get(), "emo": self.p_emo.get(), "cust": self.p_cust.get()}
            self.presets.save(n, d)
            self.cb_pre['values'] = list(self.presets.data.keys())
            self.cur_pre.set(n)
            self.set_status(f"PROFILE '{n}' SAVED")

    def load_pre(self, e):
        n = self.cur_pre.get()
        if n in self.presets.data:
            d = self.presets.data[n]
            self.p_up.set(d.get("upper", True)); self.p_low.set(d.get("lower", True)); self.p_dig.set(d.get("dig", True))
            self.p_sym.set(d.get("sym", True)); self.p_uni_math.set(d.get("math", False)); self.p_uni_lang.set(d.get("lang", False))
            self.p_uni_draw.set(d.get("box", False)); self.p_cjk.set(d.get("cjk", False)); self.p_emo.set(d.get("emo", False))
            self.p_cust.set(d.get("cust", ""))
            self.set_status(f"PROFILE '{n}' LOADED")

    def del_pre(self): 
        n = self.cur_pre.get()
        if n: self.presets.delete(n); self.cb_pre['values'] = list(self.presets.data.keys()); self.cur_pre.set(""); self.set_status("PROFILE DELETED")

# SCROLLABLE FRAME
class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        self.canvas = tk.Canvas(self, bg="#121212", highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_window = ttk.Frame(self.canvas)
        self.scrollable_window.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.scrollable_window, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True); scrollbar.pack(side="right", fill="y")
        self.scrollable_window.bind('<Enter>', self._bound_to_mousewheel)
        self.scrollable_window.bind('<Leave>', self._unbound_to_mousewheel)
    def _bound_to_mousewheel(self, event): self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
    def _unbound_to_mousewheel(self, event): self.canvas.unbind_all("<MouseWheel>")
    def _on_mousewheel(self, event):
        try: self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        except: pass