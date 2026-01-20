import sqlite3
import datetime
import hashlib
import secrets
import hmac
import struct
import time
import base64
import zlib
import json
import os
import string
import csv

# --- IRONCLAD CRYPTO ENGINE ---
class IroncladCrypto:
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        if isinstance(data, str): data = data.encode()
        nonce = secrets.token_bytes(16)
        keystream = bytearray()
        num_blocks = (len(data) // 64) + 1
        for i in range(num_blocks):
            counter = i.to_bytes(8, 'big')
            block = hmac.new(key, nonce + counter, hashlib.sha512).digest()
            keystream.extend(block)
        ciphertext = bytes(a ^ b for a, b in zip(data, keystream))
        tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
        return nonce + tag + ciphertext

    @staticmethod
    def decrypt(payload: bytes, key: bytes) -> bytes:
        try:
            nonce = payload[:16]; tag = payload[16:48]; ciphertext = payload[48:]
            calc_tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
            if not hmac.compare_digest(tag, calc_tag): return None
            keystream = bytearray()
            num_blocks = (len(ciphertext) // 64) + 1
            for i in range(num_blocks):
                counter = i.to_bytes(8, 'big')
                block = hmac.new(key, nonce + counter, hashlib.sha512).digest()
                keystream.extend(block)
            plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))
            return plaintext
        except: return None

    @staticmethod
    def get_totp_token(secret, interval=30):
        secret = secret.upper().replace(" ", "")
        if len(secret) % 8: secret += '=' * (8 - len(secret) % 8)
        try: key = base64.b32decode(secret, casefold=True)
        except: return None
        t = int(time.time()) // interval
        msg = struct.pack(">Q", t)
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[19] & 15
        code = struct.unpack(">I", digest[offset:offset+4])[0] & 0x7fffffff
        return code % 1000000

# --- DATABASE MANAGER ---
class VaultManager:
    def __init__(self, db_name="aegis_vault_v3.db"):
        self.db_name = db_name
        self.master_key = None
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect(self.db_name); c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS vault
                     (id INTEGER PRIMARY KEY, label TEXT, username BLOB,
                      email TEXT, password BLOB, url TEXT, notes BLOB, created_at TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)''')
        conn.commit(); conn.close()

    def factory_reset(self):
        try:
            if os.path.exists(self.db_name): os.remove(self.db_name)
            self.init_db(); return True
        except: return False

    def set_security(self, pin, totp_secret):
        salt = secrets.token_bytes(32)
        key = IroncladCrypto.derive_key(pin, salt)
        verify_hash = hashlib.sha256(key).hexdigest()
        conn = sqlite3.connect(self.db_name); c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('verify', ?)", (verify_hash,))
        c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('salt', ?)", (salt.hex(),))
        c.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('totp', ?)", (totp_secret,))
        conn.commit(); conn.close()
        self.master_key = key

    def change_credentials(self, new_pin, new_totp):
        if not self.master_key: return False, "Not Logged In"
        conn = sqlite3.connect(self.db_name); c = conn.cursor()
        c.execute("SELECT * FROM vault")
        rows = c.fetchall()
        decrypted_cache = []
        for r in rows:
            try:
                u = IroncladCrypto.decrypt(r[2], self.master_key).decode('utf-8')
                p = IroncladCrypto.decrypt(r[4], self.master_key).decode('utf-8')
                n = IroncladCrypto.decrypt(r[6], self.master_key).decode('utf-8')
                decrypted_cache.append({'id': r[0], 'lbl': r[1], 'usr': u, 'eml': r[3], 'pass': p, 'url': r[5], 'note': n, 'date': r[7]})
            except: pass
        new_salt = secrets.token_bytes(32)
        new_key = IroncladCrypto.derive_key(new_pin, new_salt)
        new_hash = hashlib.sha256(new_key).hexdigest()
        c.execute("UPDATE config SET value=? WHERE key='verify'", (new_hash,))
        c.execute("UPDATE config SET value=? WHERE key='salt'", (new_salt.hex(),))
        c.execute("UPDATE config SET value=? WHERE key='totp'", (new_totp,))
        for d in decrypted_cache:
            eu = IroncladCrypto.encrypt(d['usr'], new_key)
            ep = IroncladCrypto.encrypt(d['pass'], new_key)
            en = IroncladCrypto.encrypt(d['note'], new_key)
            c.execute("UPDATE vault SET username=?, password=?, notes=? WHERE id=?", (eu, ep, en, d['id']))
        conn.commit(); conn.close()
        self.master_key = new_key
        return True, "Success"

    def verify_credentials(self, pin, totp_code):
        if not os.path.exists(self.db_name): return False, "DB Missing"
        conn = sqlite3.connect(self.db_name); c = conn.cursor()
        try:
            c.execute("SELECT value FROM config WHERE key='verify'"); db_v = c.fetchone()
            c.execute("SELECT value FROM config WHERE key='salt'"); db_s = c.fetchone()
            c.execute("SELECT value FROM config WHERE key='totp'"); db_t = c.fetchone()
        except: return False, "DB Corrupt"
        conn.close()
        if not db_v or not db_s or not db_t: return False, "Vault Not Setup"
        secret = db_t[0]
        try:
            expected = IroncladCrypto.get_totp_token(secret)
            if int(totp_code) != expected:
                if int(totp_code) != IroncladCrypto.get_totp_token(secret, 30): return False, "Invalid 2FA"
        except: return False, "2FA Error"
        salt = bytes.fromhex(db_s[0])
        derived = IroncladCrypto.derive_key(pin, salt)
        if hashlib.sha256(derived).hexdigest() != db_v[0]: return False, "Invalid PIN"
        self.master_key = derived
        return True, "OK"

    def is_setup(self):
        if not os.path.exists(self.db_name): return False
        conn = sqlite3.connect(self.db_name); c = conn.cursor()
        try: c.execute("SELECT value FROM config WHERE key='verify'"); res = c.fetchone()
        except: return False
        conn.close(); return res is not None

    def add_entry(self, label, user, email, password, url, notes):
        if not self.master_key: return
        enc_user = IroncladCrypto.encrypt(user, self.master_key)
        enc_pass = IroncladCrypto.encrypt(password, self.master_key)
        enc_note = IroncladCrypto.encrypt(notes, self.master_key)
        conn = sqlite3.connect(self.db_name); c = conn.cursor()
        dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        c.execute("INSERT INTO vault (label, username, email, password, url, notes, created_at) VALUES (?,?,?,?,?,?,?)",
                  (label, enc_user, email, enc_pass, url, enc_note, dt))
        conn.commit(); conn.close()

    def update_entry(self, eid, label, user, email, password, url, notes):
        if not self.master_key: return
        enc_user = IroncladCrypto.encrypt(user, self.master_key)
        enc_pass = IroncladCrypto.encrypt(password, self.master_key)
        enc_note = IroncladCrypto.encrypt(notes, self.master_key)
        conn = sqlite3.connect(self.db_name); c = conn.cursor()
        c.execute("UPDATE vault SET label=?, username=?, email=?, password=?, url=?, notes=? WHERE id=?",
                  (label, enc_user, email, enc_pass, url, enc_note, eid))
        conn.commit(); conn.close()

    def get_entries(self, query=""):
        if not self.master_key: return []
        conn = sqlite3.connect(self.db_name); c = conn.cursor()
        if query:
            q = f"%{query}%"
            c.execute("SELECT id, label, username, password, url, notes FROM vault WHERE label LIKE ? OR url LIKE ? ORDER BY id DESC", (q, q))
        else:
            c.execute("SELECT id, label, username, password, url, notes FROM vault ORDER BY id DESC")
        raw = c.fetchall(); conn.close()
        clean = []
        for r in raw:
            try:
                dec_user = IroncladCrypto.decrypt(r[2], self.master_key).decode('utf-8')
                clean.append((r[0], r[1], dec_user, r[3], r[4], r[5]))
            except: pass
        return clean

    def get_full_decrypted_entry(self, eid):
        if not self.master_key: return None
        conn = sqlite3.connect(self.db_name); c = conn.cursor()
        c.execute("SELECT * FROM vault WHERE id=?", (eid,)); row = c.fetchone(); conn.close()
        if not row: return None
        return (row[0], row[1], IroncladCrypto.decrypt(row[2], self.master_key).decode('utf-8'), row[3], 
                IroncladCrypto.decrypt(row[4], self.master_key).decode('utf-8'), row[5], 
                IroncladCrypto.decrypt(row[6], self.master_key).decode('utf-8'), row[7])

    def delete_entry(self, eid):
        conn = sqlite3.connect(self.db_name); c = conn.cursor()
        c.execute("DELETE FROM vault WHERE id=?", (eid,)); conn.commit(); conn.close()

    def export_csv(self, filepath):
        if not self.master_key: return
        conn = sqlite3.connect(self.db_name); c = conn.cursor()
        c.execute("SELECT label, username, email, password, url, notes FROM vault")
        rows = c.fetchall(); conn.close()
        clean_rows = []
        for r in rows:
            clean_rows.append([r[0], IroncladCrypto.decrypt(r[1], self.master_key).decode('utf-8'), r[2], 
                               IroncladCrypto.decrypt(r[3], self.master_key).decode('utf-8'), r[4], 
                               IroncladCrypto.decrypt(r[5], self.master_key).decode('utf-8')])
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Label", "Username", "Email", "Password", "URL", "Notes"])
            writer.writerows(clean_rows)

    def import_csv(self, filepath):
        if not self.master_key: return 0
        count = 0
        with open(filepath, 'r', newline='', encoding='utf-8') as f:
            reader = csv.reader(f); next(reader, None) 
            conn = sqlite3.connect(self.db_name); c = conn.cursor()
            dt = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            for row in reader:
                if len(row) < 6: row += [""] * (6 - len(row))
                eu = IroncladCrypto.encrypt(row[1], self.master_key)
                ep = IroncladCrypto.encrypt(row[3], self.master_key)
                en = IroncladCrypto.encrypt(row[5], self.master_key)
                c.execute("INSERT INTO vault (label, username, email, password, url, notes, created_at) VALUES (?,?,?,?,?,?,?)",
                          (row[0], eu, row[2], ep, row[4], en, dt))
                count += 1
            conn.commit(); conn.close()
        return count

# --- FILE STREAMER ---
class OmniFileHandler:
    MAGIC_PUB = b'OMNI_V15'
    MAGIC_SEC = b'OMNI_SEC'

    @staticmethod
    def write_stream(filepath, size, pool, progress_cb, stop_event, is_char_mode=False, owner_key=None):
        rng = secrets.SystemRandom(); chunk = 1024 * 1024; written = 0; is_omni = filepath.endswith(".omni")
        mode = "wb" if is_omni else "w"; encoding = None if is_omni else "utf-8"
        header = OmniFileHandler.MAGIC_SEC if owner_key else OmniFileHandler.MAGIC_PUB
        
        with open(filepath, mode, encoding=encoding) as f:
            if is_omni: f.write(header)
            while written < size:
                if stop_event.is_set(): break
                curr = min(size - written, chunk)
                raw = "".join([rng.choice(pool) for _ in range(curr)])
                if is_omni:
                    data = zlib.compress(raw.encode())
                    if owner_key: data = IroncladCrypto.encrypt(data, owner_key)
                    f.write(len(data).to_bytes(4, 'big')); f.write(data)
                    written += curr 
                else:
                    f.write(raw)
                    written += len(raw) if is_char_mode else len(raw.encode('utf-8'))
                progress_cb(written)

    @staticmethod
    def read_omni(filepath, owner_key=None):
        with open(filepath, "rb") as f:
            magic = f.read(8)
            if magic == OmniFileHandler.MAGIC_SEC:
                if not owner_key:
                    yield "ERROR: FILE IS ENCRYPTED. LOGIN TO VIEW."; return
            elif magic == OmniFileHandler.MAGIC_PUB: pass
            else: yield "ERROR: INVALID FILE FORMAT"; return

            while True:
                sb = f.read(4)
                if not sb: break
                size = int.from_bytes(sb, 'big'); data = f.read(size)
                if len(data) != size: break
                
                if magic == OmniFileHandler.MAGIC_SEC:
                    data = IroncladCrypto.decrypt(data, owner_key)
                    if data is None: yield "ACCESS DENIED: NOT FILE OWNER"; return
                
                try: yield zlib.decompress(data).decode('utf-8')
                except: yield "[DATA CORRUPTION]"

    @staticmethod
    def claim_file(filepath, new_owner_key):
        temp_path = filepath + ".tmp"
        try:
            with open(filepath, "rb") as f_in:
                with open(temp_path, "wb") as f_out:
                    magic = f_in.read(8)
                    if magic != OmniFileHandler.MAGIC_PUB: return False
                    f_out.write(OmniFileHandler.MAGIC_SEC)
                    while True:
                        sb = f_in.read(4)
                        if not sb: break
                        size = int.from_bytes(sb, 'big')
                        data = f_in.read(size)
                        # data is compressed bytes. Encrypt it.
                        enc_data = IroncladCrypto.encrypt(data, new_owner_key)
                        f_out.write(len(enc_data).to_bytes(4, 'big'))
                        f_out.write(enc_data)
            os.replace(temp_path, filepath)
            return True
        except:
            if os.path.exists(temp_path): os.remove(temp_path)
            return False

# --- CONFIG MANAGER ---
class ConfigManager:
    def __init__(self, filename="omni_config.json"):
        self.fn = filename
        self.defaults = {"timeout_val": 5, "timeout_unit": "Minutes", "default_ext": ".omni"}
        self.data = self.defaults.copy()
        self.load()

    def load(self):
        try:
            if os.path.exists(self.fn):
                with open(self.fn, 'r') as f:
                    self.data.update(json.load(f))
        except: pass

    def get(self, key):
        return self.data.get(key, self.defaults.get(key))

    def set(self, key, value):
        self.data[key] = value
        with open(self.fn, 'w') as f: json.dump(self.data, f, indent=4)

# --- PRESETS ---
class PresetManager:
    def __init__(self, filename="omni_presets.json"):
        self.fn = filename
        self.load()

    def load(self):
        try:
            with open(self.fn, 'r') as f:
                self.data = json.load(f)
        except:
            self.data = {}

    def save(self, name, val):
        self.data[name] = val
        self._w()

    def delete(self, name):
        if name in self.data:
            del self.data[name]
            self._w()

    def _w(self):
        with open(self.fn, 'w') as f:
            json.dump(self.data, f, indent=4)