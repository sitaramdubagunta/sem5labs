# IS LAB — MIDSEM CODEBOOK (Labs 1–6)

> Ctrl+F the scenario word → copy block → change inputs → connect. Nothing here is theory.
> Stack: **Python 3 + PyCryptodome only** (`pip install -r requirements.txt`) + stdlib.
> Every code block here was executed and asserted before publishing. Traps found while testing are
> flagged with ⚠ and collected in **GOTCHAS** (end of §10).

---

# 0. PYQ ANALYSIS (what was ACTUALLY asked)

Four PYQs seen. All four are **RBAC + crypto pipeline + verify-before-decrypt** scenarios.

| # | Paper | Cipher | Hash | Signature | Roles | Storage | Twist |
|---|---|---|---|---|---|---|---|
| **P1** | HealthSecure (IT-C) | **RSA** encrypt the record itself | SHA-256 **of ciphertext** | **RSA sign** the hash | Doctor / Nurse / Admin | dict+file, timestamp | Nurse & Admin: **no private key, no decrypt** |
| **P2** | Hospital (IT-D) | **AES-128** on file + **RSA-wrapped AES key** + **ElGamal** on auth code (given p,g,h,x) | SHA-256 of AES ciphertext | — | — (sender/receiver) | 3 separate files | **Tamper 1 character** → integrity fails → refuse decrypt |
| **P3** | MediSecure (IT-B) | **AES, user-supplied key AND IV** | SHA-256 of ciphertext | **RSA sign** | Patient / Doctor / Auditor | `.txt` read, store iv+hash+sig+ts | Auditor: metadata only |
| **P4** | SecureVault | **DES-CBC** + generated IV | SHA-256 of ciphertext | **ElGamal signature** (not RSA!) | Client / Lawyer / Compliance Officer | file, verification log + timestamp | Compliance Report; officer must NOT decrypt |

### Recurring pattern (appears in 4/4)
```
plaintext → ENCRYPT → SHA256(ciphertext) → SIGN(hash) → store {ct, iv, hash, sig, ts}
reader → recompute hash → compare → verify signature → decrypt ONLY if both pass
```
→ **Section 8 `secure_pack` / `secure_unpack` solves all four.** Swap cipher + swap signer.

### What is asked, tagged

| Item | Status |
|---|---|
| AES (128/192/256, CBC/CTR/ECB) | `[LAB]` L2 Ex2,3,5 + `[PYQ]` P2,P3 |
| DES / 3DES | `[LAB]` L2 Ex1,4 + **`[PYQ]` P4 (DES-CBC)** |
| IV / nonce | `[LAB]` L2 Add.Ex4,5 + `[PYQ]` P3 (user-given), P4 (generated) |
| RSA encrypt/decrypt | `[LAB]` L3 Ex1 + **`[PYQ]` P1 (data), P2 (AES key)** |
| Textbook RSA (n=323,e=5,d=173) | `[LAB]` L3 Add.Ex3 |
| ElGamal **encryption** (p=7919,g=2,h=6465,x=2999) | `[LAB]` L3 Ex3, Add.Ex1 + **`[PYQ]` P2 (given params)** |
| ElGamal **signature** | `[LAB]` L6 Ex1 + **`[PYQ]` P4** |
| Diffie-Hellman | `[LAB]` L3 Ex5, L4 Q1, L6 Ex2 |
| ECC / ECDH | `[LAB]` L3 Ex2,4 |
| Rabin | `[LAB]` L4 Q2 |
| Key mgmt: gen/store/revoke/renew | `[LAB]` L4 Q2 |
| Audit logging | `[LAB]` L4 Q2 + **`[PYQ]` P4 (compliance report)** |
| RBAC | `[LAB]` L4 theory + **`[PYQ]` P1,P3,P4** |
| Custom hash (5381/×33/mask) | `[LAB]` L5 Ex1 |
| MD5 vs SHA1 vs SHA256 timing + collision | `[LAB]` L5 Ex3 |
| **Sockets + hash verify** | `[LAB]` L5 Ex2 |
| **Multipart socket** | `[LAB]` L5 Add.Ex1 |
| RSA digital signature | `[LAB]` L6 + `[PYQ]` P1,P3 |
| CIA triad = RSA enc + sign + SHA | `[LAB]` L6 final line |
| Classical ciphers + brute force / known-plaintext | `[LAB]` L1 (not in these PYQs, still examinable) |

`[COMBINATION]` most likely to appear: **AES/DES + SHA-256 + signature + RBAC + timestamp + file**.

---

# 0.5 PASTE ORDER — what every block depends on

Every code block below starts with a `# NEEDS:` line. This is the master map.
**Paste top-down in this order and nothing can be missing.**

```
1. §1 utils            (b64, ub64, hx, uhx, S, ts, read_file, write_file, save_json, load_json)
2. §1 fix_key          (+ des3_key only if 3DES)
3. §3 imports          (AES, DES, DES3, pad, unpad, get_random_bytes)
4. §3 _alg, sym_enc, sym_dec        <- needs S
5. §3 enc_file, dec_file            <- needs _alg/sym_enc/sym_dec + read_file/write_file
6. §4 imports          (RSA, ECC, PKCS1_OAEP, getPrime, inverse, bytes_to_long, long_to_bytes, GCD)
7. §4 rsa_keys, rsa_enc, rsa_dec, rsa_enc_long, rsa_dec_long
8. §4 eg_* + dlog      (ElGamal ENCRYPTION)   |   §4 rabin_*   |   §4 dh_*
9. §6 sha256_hex, verify_hash, tamper         <- needs S
10. §7 imports (pkcs1_15, SHA256) + rsa_sign, rsa_verify
11. §7 egs_* (ElGamal SIGNATURE)              <- needs sha256_hex, getPrime, GCD
12. §5 audit  ->  then PERMS + allow          (allow calls audit, so audit goes first)
13. §8.0 secure_pack, secure_unpack           <- needs 4, 9, 10, (11), §1
14. your own menu / driver code
```

### The 5 dependency traps

| Trap | Fix |
|---|---|
| `sym_enc` fails with `NameError: S` | `S` lives in the §1 utils block, not in §3. |
| `allow` fails with `NameError: audit` | paste `audit` **before** `PERMS`/`allow`. |
| `km_generate` fails with `NameError: load_json` | it needs `load_json`, `save_json`, `ts` from §1 **and** `audit` from §5. |
| `secure_unpack` fails with `NameError: egs_verify` | only needed when `sign="EG"`; paste §7 `egs_*` too. |
| `enc_file` fails with `NameError: _alg` | `_alg` is the 2-line helper directly above `sym_enc`. Copy it too. |

**Fastest rule:** if you get `NameError: X is not defined`, Ctrl+F `def X` in this file and paste that block.

---

# 1. COMMON UTILITIES

```python
# NEEDS: nothing. THIS IS THE BASE BLOCK - paste it first in every answer.
# ===== utils.py - paste at top of EVERY answer =====
import base64, json, os, time, socket, struct, hashlib, random
from datetime import datetime

b64  = lambda b: base64.b64encode(b).decode()          # bytes -> str
ub64 = lambda s: base64.b64decode(s)                   # str   -> bytes
hx   = lambda b: b.hex()                               # bytes -> hex str
uhx  = lambda s: bytes.fromhex(s)                      # hex   -> bytes
S    = lambda x: x.encode() if isinstance(x, str) else x   # str -> bytes (safe)
ts   = lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def read_file(p, binary=False):
    if binary: return open(p, "rb").read()
    return open(p, "r", encoding="utf-8", newline="").read()   # newline="" = no \r\n mangling

def write_file(p, data):
    if isinstance(data, bytes): open(p, "wb").write(data)
    else: open(p, "w", encoding="utf-8", newline="").write(data)

def save_json(p, obj):  json.dump(obj, open(p, "w"), indent=2)
def load_json(p):       return json.load(open(p)) if os.path.exists(p) else []

def show(label, v):     # pretty-print bytes safely
    print(f"{label}: {b64(v) if isinstance(v, bytes) else v}")
```

**Key sizing helper — the #1 exam trap** (question gives `"0123456789ABCDEF0123456789ABCDEF"` for AES-**128**: that is 32 *hex chars* = 16 bytes, not 32 ASCII bytes).

```python
# NEEDS: nothing.
def fix_key(k, n):
    """n = 8 (DES) | 16/24/32 (AES-128/192/256) | 24 (3DES). Auto-detects hex."""
    if isinstance(k, str):
        s = k.strip()
        if len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
            k = bytes.fromhex(s)            # hex string  -> bytes
        else:
            k = s.encode()                  # plain ASCII -> bytes
    return (k + b"\0" * n)[:n]              # pad/truncate to exact size
```

| Given in question | Call |
|---|---|
| `"A1B2C3D4"` DES | `fix_key("A1B2C3D4", 8)` → hex→4B, padded to 8 ✔ (or `b"A1B2C3D4"` = 8 ASCII; either passes) |
| AES-128 32-hex-char key | `fix_key(k, 16)` |
| AES-192 | `fix_key(k, 24)` |
| AES-256 64-hex-char key | `fix_key(k, 32)` |
| 3DES 48-hex-char key | **`des3_key(k)`** (see below — plain `fix_key` crashes) |
| Random | `get_random_bytes(16)` |

⚠ **3DES trap (verified):** the manual's key `"1234567890ABCDEF"×3` gives K1=K2=K3, and PyCryptodome raises
`ValueError: Triple DES key degenerates to single DES`. Use:
```python
# NEEDS: fix_key (above)  +  `from Crypto.Cipher import DES3`
from Crypto.Cipher import DES3
def des3_key(k):
    k = fix_key(k, 24)
    try:    return DES3.adjust_key_parity(k)
    except ValueError:                      # K1==K2==K3 -> break it (0x01 is the parity bit,
        b = bytearray(k); b[8] ^= 0x02; b[16] ^= 0x04   # so flipping 0x01 does nothing)
        return DES3.adjust_key_parity(bytes(b))
```

---

# 2. LAB 1 — CLASSICAL CIPHERS

```python
# NEEDS: nothing. These 3 helpers are used by EVERY Lab-1 cipher below.
A = lambda c: ord(c) - 65                     # 'A'->0
L = lambda n: chr(n % 26 + 65)                # 0->'A'
clean = lambda t: "".join(ch for ch in t.upper() if ch.isalpha())   # drop spaces
```

### Additive / Caesar (key=20) `[LAB L1.1a]`
```python
# NEEDS: A, L, clean (block above)
def add_enc(t, k): return "".join(L(A(c) + k) for c in clean(t))
def add_dec(c, k): return "".join(L(A(x) - k) for x in clean(c))
```

### Multiplicative (key=15) `[LAB L1.1b]`
```python
# NEEDS: A, L, clean
def mul_enc(t, k): return "".join(L(A(c) * k) for c in clean(t))
def mul_dec(c, k):
    ki = pow(k, -1, 26)
    return "".join(L(A(x) * ki) for x in clean(c))
```

### Affine (a,b) = (15,20) `[LAB L1.1c]`
```python
# NEEDS: A, L, clean
def aff_enc(t, a, b): return "".join(L(a * A(c) + b) for c in clean(t))
def aff_dec(c, a, b):
    ai = pow(a, -1, 26)
    return "".join(L(ai * (A(x) - b)) for x in clean(c))
```

### Vigenere (key="dollars" / "HEALTH") `[LAB L1.2, Add.3]`
```python
# NEEDS: A, L, clean
def vig_enc(t, key):
    t, key = clean(t), clean(key)
    return "".join(L(A(c) + A(key[i % len(key)])) for i, c in enumerate(t))
def vig_dec(c, key):
    c, key = clean(c), clean(key)
    return "".join(L(A(x) - A(key[i % len(key)])) for i, x in enumerate(c))
```

### Autokey (key = 7) `[LAB L1.2]`
```python
# NEEDS: A, L, clean
def auto_enc(t, k):
    t = clean(t); out = []; prev = k                  # k is a NUMBER here
    for ch in t:
        out.append(L(A(ch) + prev)); prev = A(ch)     # plaintext feeds the key
    return "".join(out)
def auto_dec(c, k):
    c = clean(c); out = []; prev = k
    for x in c:
        p = A(x) - prev; out.append(L(p)); prev = p % 26
    return "".join(out)
```

### Playfair (key "GUIDANCE") `[LAB L1.3]`
```python
# NEEDS: clean
def pf_matrix(key):
    key = clean(key).replace("J", "I"); seen = []
    for c in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if c not in seen and c != "J": seen.append(c)
    return [seen[i:i+5] for i in range(0, 25, 5)]

def pf_pairs(t):
    t = clean(t).replace("J", "I"); out = []; i = 0
    while i < len(t):
        a = t[i]; b = t[i+1] if i+1 < len(t) else "X"
        if a == b: b, i = "X", i + 1
        else: i += 2
        out.append(a + b)
    return out

def pf_pos(m, c):
    for r in range(5):
        if c in m[r]: return r, m[r].index(c)

def playfair(text, key, enc=True):
    m = pf_matrix(key); d = 1 if enc else -1; out = ""
    for a, b in pf_pairs(text):
        r1, c1 = pf_pos(m, a); r2, c2 = pf_pos(m, b)
        if r1 == r2:   out += m[r1][(c1+d) % 5] + m[r2][(c2+d) % 5]
        elif c1 == c2: out += m[(r1+d) % 5][c1] + m[(r2+d) % 5][c2]
        else:          out += m[r1][c2] + m[r2][c1]
    return out
# playfair("The key is hidden under the door pad", "GUIDANCE", True)
```

### Hill cipher 2×2, K=[[3,3],[2,7]] `[LAB L1.4]`
```python
# NEEDS: A, L, clean   (hill_dec also needs hill_enc)
def hill_enc(t, K):
    t = clean(t)
    if len(t) % 2: t += "X"
    out = ""
    for i in range(0, len(t), 2):
        a, b = A(t[i]), A(t[i+1])
        out += L(K[0][0]*a + K[0][1]*b) + L(K[1][0]*a + K[1][1]*b)
    return out

def hill_dec(c, K):
    det = (K[0][0]*K[1][1] - K[0][1]*K[1][0]) % 26
    di  = pow(det, -1, 26)
    I   = [[( K[1][1]*di) % 26, (-K[0][1]*di) % 26],
           [(-K[1][0]*di) % 26, ( K[0][0]*di) % 26]]
    return hill_enc(c, I)
# hill_enc("We live in an insecure world", [[3,3],[2,7]])
```

## Attacks that are actually in the manual

### Known-plaintext shift: "CIW"→"yes", then decode "XVIEWYWI" `[LAB L1.5]`
**Answer: known-plaintext attack.** Key = A('C') − A('Y') = 2−24 = −22 ≡ 4.
```python
# NEEDS: A, add_dec
k = (A("C") - A("Y")) % 26
print(k, add_dec("XVIEWYWI", k))
# -> key = 4, plaintext = "TREASUSE"  (the manual has a typo: "XVIEWYVI" would give TREASURE)
```

### Brute force affine with crib "ab"→"GL" `[LAB L1.6]`
```python
# NEEDS: aff_enc, aff_dec
CT = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
for a in range(1, 26):
    if a % 2 == 0 or a == 13: continue          # a must be coprime with 26
    for b in range(26):
        if aff_enc("ab", a, b) == "GL":
            print("key =", (a, b), aff_dec(CT, a, b))
# -> direct solve: b = A('G') = 6 ; a = A('L') - b = 5
```

### Brute force additive, key near 13 `[LAB L1 Add.1]`
```python
# NEEDS: add_dec
CT = "NCJAEZRCLASLYODEPRLYZRCLASJLCPEHZDTOPDZOLNBY"
for k in range(26):                 # or: for k in (11,12,13,14,15)
    print(k, add_dec(CT, k))        # eyeball for readable English
```

### Transposition / permutation attack `[LAB L1 Add.2]`
Eve types `abcdefghi` → sees `CABDEHFGL`.
**(a) Chosen-plaintext attack. (b) Permutation key size = 3** (blocks of 3: `abc→CAB`, `def→DEH`… the mapping repeats every 3 chars).
```python
# NEEDS: clean   (the brute-force part also needs `from itertools import permutations`)
def perm_enc(t, key):       # key = tuple of 0-based positions, e.g. (2,0,1)
    t = clean(t); n = len(key)
    t += "X" * ((-len(t)) % n)
    return "".join("".join(t[i+key[j]] for j in range(n)) for i in range(0, len(t), n))

def perm_dec(c, key):
    n = len(key); inv = [key.index(j) for j in range(n)]
    return "".join("".join(c[i+inv[j]] for j in range(n)) for i in range(0, len(c), n))

# recover key by brute force from a known plaintext/ciphertext pair:
from itertools import permutations
for n in (2, 3, 4):
    for k in permutations(range(n)):
        if perm_enc("abcdefghi", k).startswith("CAB"): print(n, k)
```

---

# 3. LAB 2 — AES / DES / 3DES

```python
# NEEDS: nothing. Paste these imports before sym_enc/sym_dec.
from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
```

## ONE reusable block cipher function (covers AES-128/192/256, DES, 3DES, ECB/CBC/CTR/CFB/OFB)

```python
# NEEDS: the imports above  +  S (from sec 1 utils)
def _alg(name):
    return {"AES": (AES, 16), "DES": (DES, 8), "DES3": (DES3, 8)}[name]

def sym_enc(data, key, alg="AES", mode="CBC", iv=None):
    """returns (iv, ciphertext). iv is b'' for ECB. Key size decides AES-128/192/256."""
    M, bs = _alg(alg); data = S(data)
    if mode == "ECB":
        return b"", M.new(key, M.MODE_ECB).encrypt(pad(data, bs))
    if mode == "CBC":
        iv = iv or get_random_bytes(bs)
        return iv, M.new(key, M.MODE_CBC, iv).encrypt(pad(data, bs))
    if mode == "CTR":                                   # nonce = half block
        iv = iv or get_random_bytes(bs // 2)
        return iv, M.new(key, M.MODE_CTR, nonce=iv).encrypt(data)   # no padding
    if mode in ("CFB", "OFB"):
        iv = iv or get_random_bytes(bs)
        return iv, M.new(key, getattr(M, "MODE_" + mode), iv).encrypt(data)

def sym_dec(ct, key, alg="AES", mode="CBC", iv=b""):
    M, bs = _alg(alg)
    if mode == "ECB": return unpad(M.new(key, M.MODE_ECB).decrypt(ct), bs)
    if mode == "CBC": return unpad(M.new(key, M.MODE_CBC, iv).decrypt(ct), bs)
    if mode == "CTR": return M.new(key, M.MODE_CTR, nonce=iv).decrypt(ct)
    if mode in ("CFB", "OFB"):
        return M.new(key, getattr(M, "MODE_" + mode), iv).decrypt(ct)
```

### Usage — every Lab-2 exercise in 6 lines
```python
# NEEDS: _alg, sym_enc, sym_dec  +  fix_key, des3_key, hx, uhx (sec 1)
# L2.1 DES "Confidential Data", key "A1B2C3D4"
k = fix_key("A1B2C3D4", 8)
iv, ct = sym_enc("Confidential Data", k, "DES", "ECB"); print(hx(ct))
print(sym_dec(ct, k, "DES", "ECB").decode())

# L2.2 AES-128 "Sensitive Information", key "0123456789ABCDEF0123456789ABCDEF"
k = fix_key("0123456789ABCDEF0123456789ABCDEF", 16)          # hex -> 16 bytes
iv, ct = sym_enc("Sensitive Information", k, "AES", "ECB")

# L2.4 3DES "Classified Text"  (48 hex chars -> 24 bytes) -- MUST use des3_key
k = des3_key("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF")
iv, ct = sym_enc("Classified Text", k, "DES3", "ECB")

# L2.5 AES-192 "Top Secret Data" (pad the given 32-hex key up to 24 bytes)
k = fix_key("FEDCBA9876543210FEDCBA9876543210", 24)
iv, ct = sym_enc("Top Secret Data", k, "AES", "ECB")

# Add.4 DES-CBC key "A1B2C3D4" iv "12345678"   <-- PYQ P4 shape
k, iv0 = fix_key("A1B2C3D4", 8), b"12345678"
iv, ct = sym_enc("Secure Communication", k, "DES", "CBC", iv0)
print(sym_dec(ct, k, "DES", "CBC", iv).decode())

# Add.5 AES-CTR nonce "0000000000000000" (16 hex chars -> 8 bytes)
k  = fix_key("0123456789ABCDEF0123456789ABCDEF", 16)
nz = fix_key("0000000000000000", 8)
nz, ct = sym_enc("Cryptography Lab Exercise", k, "AES", "CTR", nz)

# Add.2 DES on raw hex blocks
blk = uhx("54686973206973206120636f6e666964656e7469616c206d657373616765")
iv, ct = sym_enc(blk, fix_key("A1B2C3D4E5F60708", 8), "DES", "ECB")
```

### AES key-size table
| Want | key bytes | how |
|---|---|---|
| AES-128 | 16 | `fix_key(k,16)` / `get_random_bytes(16)` |
| AES-192 | 24 | `fix_key(k,24)` |
| AES-256 | 32 | `fix_key(k,32)` |
| DES | 8 | `fix_key(k,8)` |
| 3DES | 24 (or 16) | `fix_key(k,24)` |

### File encrypt / decrypt `[PYQ P2, P3]`
```python
# NEEDS: _alg, sym_enc, sym_dec (sec 3)  +  read_file, write_file (sec 1)
def enc_file(src, dst, key, alg="AES", mode="CBC", iv=None):
    iv, ct = sym_enc(read_file(src, binary=True), key, alg, mode, iv)
    write_file(dst, iv + ct)                    # IV prepended -> self-contained file
    return iv, ct

def dec_file(src, dst, key, alg="AES", mode="CBC"):
    bs   = _alg(alg)[1]; blob = read_file(src, binary=True)
    n    = 0 if mode == "ECB" else (bs // 2 if mode == "CTR" else bs)
    iv, ct = blob[:n], blob[n:]
    pt = sym_dec(ct, key, alg, mode, iv); write_file(dst, pt); return pt
```

### Timing comparison DES vs AES-256 `[LAB L2.3]`
```python
# NEEDS: sym_enc, sym_dec (sec 3)  +  get_random_bytes, `import time`
msg = b"Performance Testing of Encryption Algorithms" * 100
for alg, n in (("DES", 8), ("AES", 16), ("AES", 32), ("DES3", 24)):
    k = get_random_bytes(n)
    t0 = time.perf_counter(); iv, ct = sym_enc(msg, k, alg, "CBC"); t1 = time.perf_counter()
    sym_dec(ct, k, alg, "CBC", iv);                                 t2 = time.perf_counter()
    print(f"{alg}-{n*8:<3} enc {(t1-t0)*1000:7.3f} ms | dec {(t2-t1)*1000:7.3f} ms")
```

---

# 4. LAB 3 — RSA / ELGAMAL / DIFFIE–HELLMAN / ECC

```python
# NEEDS: nothing. Paste these imports before any RSA/ElGamal/DH/ECC block.
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD
```

## RSA — library version `[LAB L3.1] [PYQ P1, P2]`
```python
# NEEDS: the imports above  +  S (sec 1)
def rsa_keys(bits=2048):
    k = RSA.generate(bits); return k, k.publickey()     # (private, public)

def rsa_enc(data, pub):  return PKCS1_OAEP.new(pub).encrypt(S(data))
def rsa_dec(ct, priv):   return PKCS1_OAEP.new(priv).decrypt(ct)
```
**Limit:** OAEP can encrypt only `keysize/8 − 42` bytes (2048-bit → 214 B). For a whole record `[PYQ P1]` use chunking:
```python
# NEEDS: PKCS1_OAEP, S (sec 1)
def rsa_enc_long(data, pub):
    k = pub.size_in_bytes(); c = PKCS1_OAEP.new(pub); data = S(data)
    return b"".join(c.encrypt(data[i:i+k-42]) for i in range(0, len(data), k - 42))

def rsa_dec_long(ct, priv):
    k = priv.size_in_bytes(); c = PKCS1_OAEP.new(priv)
    return b"".join(c.decrypt(ct[i:i+k]) for i in range(0, len(ct), k))
```
Save / load keys:
```python
# NEEDS: rsa_keys  +  read_file, write_file (sec 1)
write_file("priv.pem", priv.export_key()); write_file("pub.pem", pub.export_key())
priv = RSA.import_key(read_file("priv.pem", True))
print("n =", priv.n, "\ne =", priv.e, "\nd =", priv.d)      # "display RSA values" [PYQ P2]
```

## Textbook RSA — when p,q or (n,e,d) are GIVEN `[LAB L3 Add.3]`
```python
# NEEDS: GCD (imported above). Pure Python - no other block required.
def rsa_kg(p, q, e=None):
    n, phi = p * q, (p - 1) * (q - 1)
    if e is None:
        e = 3
        while GCD(e, phi) != 1: e += 2
    d = pow(e, -1, phi)
    return (n, e), (n, d)

def rsa_enc_tb(msg, n, e):                  # per-character (small n, e.g. n=323)
    return [pow(ord(c), e, n) for c in msg]
def rsa_dec_tb(cts, n, d):
    return "".join(chr(pow(c, d, n)) for c in cts)

# n=323, e=5, d=173 -> "Cryptographic Protocols"
ct = rsa_enc_tb("Cryptographic Protocols", 323, 5); print(ct)
print(rsa_dec_tb(ct, 323, 173))

# whole message as one integer (when n is large enough):
m  = bytes_to_long(b"Asymmetric Encryption")
c  = pow(m, e, n); print(long_to_bytes(pow(c, d, n)))
```
**Attack: n with small/close primes** `[LAB L4 Add.Q2]`
```python
# NEEDS: nothing (uses `import math` internally).
def factor_n(n):
    import math
    f = math.isqrt(n)                       # Fermat: primes close together
    if f * f < n: f += 1                    # start at ceil(sqrt(n)) or f*f-n goes negative
    while True:
        b2 = f*f - n
        r  = math.isqrt(b2)
        if r*r == b2: return f - r, f + r
        f += 1
p, q = factor_n(323); print(p, q, "-> d =", pow(5, -1, (p-1)*(q-1)))
```

## ElGamal — ENCRYPTION, pure Python `[LAB L3.3, Add.1] [PYQ P2]`
```python
# NEEDS: getPrime (sec 4 imports)  +  `import random`   (dlog is included here, so paste this whole block)
def dlog(h, g, p, limit=10**7):               # brute-force discrete log (fine for p=7919)
    v = 1                                     # kept HERE so this block pastes top-down
    for i in range(limit):                    # (used by the given-parameter version below)
        if v == h: return i
        v = v * g % p
    return None

def eg_keygen(bits=256):
    p = getPrime(bits); g = 2
    x = random.randrange(2, p - 1); h = pow(g, x, p)
    return (p, g, h), x                       # public, private

def eg_enc(m, p, g, h):                       # m = int  (0 <= m < p)
    k  = random.randrange(2, p - 2)
    return pow(g, k, p), (m * pow(h, k, p)) % p       # (c1, c2)

def eg_dec(c1, c2, p, x):
    return (c2 * pow(pow(c1, x, p), -1, p)) % p

# --- text helpers (per character: safest when p is small like 7919) ---
def eg_enc_text(t, p, g, h): return [eg_enc(ord(c), p, g, h) for c in t]
def eg_dec_text(ct, p, x):   return "".join(chr(eg_dec(a, b, p, x)) for a, b in ct)

# GIVEN-PARAMETER VERSION  [LAB L3 Add.1] [PYQ P2 "authorization code"]
p, g, h, x = 7919, 2, 6465, 2999
if pow(g, x, p) != h:          # <-- ALWAYS CHECK THIS FIRST (see trap below)
    x = dlog(h, g, p)          # recover the real private key: x = 355
ct = eg_enc_text("Asymmetric Algorithms", p, g, h)
print(ct); print(eg_dec_text(ct, p, x))

# whole-message-as-int version (needs big p):
(p2, g2, h2), x2 = eg_keygen(512)
m = bytes_to_long(b"Confidential Data")
c1, c2 = eg_enc(m, p2, g2, h2); print(long_to_bytes(eg_dec(c1, c2, p2, x2)))
```

⚠ **VERIFIED TRAP — the manual's ElGamal numbers don't match each other.**
`2^2999 mod 7919 = 3868`, **not** 6465. If you encrypt with `h=6465` and decrypt with `x=2999`
you get **silent garbage, not an error**. Two legal fixes — say which one you used:
```python
# NEEDS: nothing. (dlog is ALREADY included at the top of the ElGamal block above -
#        it is repeated here only so the trap explanation is self-contained.)
def dlog(h, g, p, limit=10**7):       # brute-force discrete log (fine for p=7919)
    v = 1
    for i in range(limit):
        if v == h: return i
        v = v * g % p
    return None
# FIX A (keep given h): x = dlog(6465, 2, 7919)  -> x = 355    verified
# FIX B (keep given x): h = pow(2, 2999, 7919)   -> h = 3868   verified
```
Sanity check to write in EVERY ElGamal answer: `assert pow(g, x, p) == h`.

## Diffie–Hellman `[LAB L3.5, L4 Q1, L6 Ex2]`
```python
# NEEDS: `import random`  +  hashlib, long_to_bytes (only for the AES-key line)
def dh_keypair(p, g):
    a = random.randrange(2, p - 2); return a, pow(g, a, p)     # private, public

def dh_shared(other_pub, my_priv, p):
    return pow(other_pub, my_priv, p)

# GIVEN p,g version
p, g = 23, 5                                  # or getPrime(512), 2
a, A = dh_keypair(p, g); b, B = dh_keypair(p, g)
assert dh_shared(B, a, p) == dh_shared(A, b, p)
sk = dh_shared(B, a, p); print("shared secret =", sk)

# turn the shared secret into a usable AES key:
aes_key = hashlib.sha256(long_to_bytes(sk)).digest()[:16]

# timing [LAB L3.5]
t0 = time.perf_counter(); a, A = dh_keypair(p, g); t1 = time.perf_counter()
dh_shared(B, a, p);                              t2 = time.perf_counter()
print(f"keygen {(t1-t0)*1000:.3f} ms | exchange {(t2-t1)*1000:.3f} ms")
```

## ECC — only what the manual needs (ECDH → AES) `[LAB L3.2, L3.4]`
PyCryptodome has no direct ECC "encrypt". The manual itself says ECC is used for key exchange → **do ECDH, derive an AES key, encrypt with AES.**
```python
# NEEDS: ECC (sec 4 imports), `import hashlib`  +  sym_enc, sym_dec (sec 3)
def ecc_keys(curve="P-256"):                      # P-256 == secp256r1
    k = ECC.generate(curve=curve); return k, k.public_key()

def ecdh_key(my_priv, their_pub):
    s = their_pub.pointQ * my_priv.d               # shared point
    return hashlib.sha256(int(s.x).to_bytes(32, "big")).digest()   # 32B AES-256 key

# "encrypt with the public key, decrypt with the private key"  [LAB L3.2]
a_priv, a_pub = ecc_keys(); b_priv, b_pub = ecc_keys()
k1 = ecdh_key(a_priv, b_pub); k2 = ecdh_key(b_priv, a_pub); assert k1 == k2
iv, ct = sym_enc("Secure Transactions", k1, "AES", "CBC")
print(sym_dec(ct, k2, "AES", "CBC", iv).decode())
```
RSA vs ECC performance `[LAB L3.4]`
```python
# NEEDS: RSA, ECC, `import time`
for name, fn in [("RSA-2048", lambda: RSA.generate(2048)),
                 ("ECC P-256", lambda: ECC.generate(curve="P-256"))]:
    t0 = time.perf_counter(); fn(); print(name, "keygen", f"{time.perf_counter()-t0:.3f}s")
```

---

# 5. LAB 4 — RABIN / KEY MANAGEMENT / RBAC / AUDIT

## Rabin `[LAB L4 Q2]`
```python
# NEEDS: getPrime, inverse, bytes_to_long, long_to_bytes (sec 4 imports)  +  S (sec 1)
def rabin_keys(bits=512):
    def p3mod4(b):
        while True:
            p = getPrime(b)
            if p % 4 == 3: return p
    p, q = p3mod4(bits // 2), p3mod4(bits // 2)
    return p * q, (p, q)                          # public n, private (p,q)

def rabin_enc(m, n):
    m = bytes_to_long(S(m)) if not isinstance(m, int) else m
    return pow(m, 2, n)

def rabin_dec(c, p, q):
    n  = p * q
    mp = pow(c, (p + 1) // 4, p); mq = pow(c, (q + 1) // 4, q)
    yp, yq = inverse(p, q), inverse(q, p)
    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = n - r1
    r3 = (yp * p * mq - yq * q * mp) % n
    r4 = n - r3
    return [r1, r2, r3, r4]                       # 4 roots; pick the readable one

def rabin_pick(roots):
    for r in roots:
        try:
            t = long_to_bytes(r).decode()
            if t.isprintable(): return t
        except Exception: pass

n, (p, q) = rabin_keys(512)
c = rabin_enc("Patient Record 42", n)
print(rabin_pick(rabin_dec(c, p, q)))
```
**Rabin vs RSA trade-off (one-liner for the viva):** Rabin encryption is a single squaring (faster than RSA's `m^e`), security provably equals factoring, **but** decryption yields 4 candidates needing redundancy to disambiguate, and it is totally broken under chosen-ciphertext attack — RSA has unique decryption and mature padding (OAEP).

## Key management service: generate / store / distribute / revoke / renew `[LAB L4 Q2]`
```python
# NEEDS: load_json, save_json, ts (sec 1) + RSA, datetime + audit -- WHICH IS THE BLOCK BELOW,
#        so scroll down and paste `audit` FIRST, or every km_* call dies with NameError.
KEYSTORE = "keystore.json"

def km_generate(entity, bits=1024):
    k = RSA.generate(bits)                        # swap for rabin_keys() if asked
    db = load_json(KEYSTORE) or {}
    db[entity] = {"pub": k.publickey().export_key().decode(),
                  "priv": k.export_key().decode(),
                  "created": ts(), "status": "ACTIVE"}
    save_json(KEYSTORE, db); audit("GENERATE", entity); return k

def km_get(entity, part="pub"):
    db  = load_json(KEYSTORE) or {}; rec = db.get(entity)
    if not rec or rec["status"] != "ACTIVE":
        audit("DENIED", entity); return None
    audit("DISTRIBUTE", entity); return RSA.import_key(rec[part])

def km_revoke(entity):
    db = load_json(KEYSTORE); db[entity]["status"] = "REVOKED"
    db[entity]["revoked"] = ts(); save_json(KEYSTORE, db); audit("REVOKE", entity)

def km_renew(entity, bits=1024):                  # "every 12/24 months"
    audit("RENEW", entity); return km_generate(entity, bits)

def km_expired(entity, months=12):
    c = datetime.strptime(load_json(KEYSTORE)[entity]["created"], "%Y-%m-%d %H:%M:%S")
    return (datetime.now() - c).days > months * 30
```

## Audit log `[LAB L4] [PYQ P4 compliance report]`
```python
# NEEDS: ts, read_file, write_file (sec 1)
LOG = "audit.log"
def audit(action, who, detail=""):
    line = f"[{ts()}] {action:<12} {who:<12} {detail}"
    open(LOG, "a").write(line + "\n"); print(line)

def report(path="compliance_report.txt"):         # [PYQ P4]
    body = f"COMPLIANCE REPORT\nGenerated: {ts()}\n{'-'*50}\n" + read_file(LOG)
    write_file(path, body); print(body)
```

## RBAC `[LAB L4 theory] [PYQ P1, P3, P4]`
```python
# NEEDS: audit (block above)
PERMS = {                       # <-- rename roles/actions to match the question
         "Doctor": {"create", "view", "verify", "decrypt"},
         "Nurse":  {"view", "verify"},
         "Admin":  {"view_meta", "verify"},
}
def allow(role, action):
    ok = action in PERMS.get(role, set())
    audit("ALLOW" if ok else "DENY", role, action)
    if not ok: print(f"[ACCESS DENIED] Role '{role}' cannot perform '{action}'")
    return ok

# usage guard at the top of every menu handler:
# if not allow(role, "decrypt"): return
```
Role sets for the four PYQs (copy the right one):
```python
# NEEDS: nothing - these are just three ready-made PERMS tables.
P1 = {"Doctor": {"create","view","verify","decrypt"}, "Nurse": {"view","verify"},
      "Admin":  {"view_meta","verify"}}
P3 = {"Patient": {"create","view"}, "Doctor": {"view","verify","decrypt"},
      "Auditor": {"view_meta","verify"}}
P4 = {"Client": {"create","view"}, "Lawyer": {"view","verify","decrypt"},
      "Compliance": {"view_meta","verify","report"}}
```

---

# 6. LAB 5 — HASHING

```python
# NEEDS: nothing. Paste before any hashing block.
import hashlib
from Crypto.Hash import SHA256, SHA1, MD5
```

### Custom hash: init 5381, ×33, +ord, mix, 32-bit mask `[LAB L5.1]`
```python
# NEEDS: S (sec 1)
def my_hash(s):
    h = 5381
    for ch in S(s).decode(errors="ignore") if isinstance(s, bytes) else s:
        h = (h * 33 + ord(ch)) & 0xFFFFFFFF      # djb2 + 32-bit mask
        h ^= (h >> 16)                            # bitwise mixing
        h  = (h + (h << 5)) & 0xFFFFFFFF
    return h & 0xFFFFFFFF
print(hex(my_hash("Information Security")))
```

### Standard hashes — string / bytes / file
```python
# NEEDS: S (sec 1)  +  `import hashlib`, SHA256 (for sha256_obj)
def sha256_hex(d):  return hashlib.sha256(S(d)).hexdigest()
def md5_hex(d):     return hashlib.md5(S(d)).hexdigest()
def sha1_hex(d):    return hashlib.sha1(S(d)).hexdigest()

def hash_file(path, algo="sha256"):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(8192), b""): h.update(blk)
    return h.hexdigest()

# PyCryptodome equivalents (needed for signing):
def sha256_obj(d): return SHA256.new(S(d))
```

### Compare / integrity check
```python
# NEEDS: sha256_hex (above)
def verify_hash(data, stored_hex):
    ok = sha256_hex(data) == stored_hex
    print("INTEGRITY:", "PASS" if ok else "FAIL (data modified)")
    return ok
```

### Tamper one byte / one character `[PYQ P2 — explicitly asked]`
```python
# NEEDS: S (sec 1).  The demo lines also need sym_enc, fix_key, sha256_hex, verify_hash.
def tamper(data, pos=0):
    """Flip one byte of ciphertext to DEMONSTRATE integrity failure."""
    b = bytearray(S(data)); b[pos] = (b[pos] + 1) % 256; return bytes(b)

def tamper_char(text, pos=0, new="X"):            # for string/hex/base64 ciphertext
    return text[:pos] + new + text[pos+1:]

# demo
iv, ct = sym_enc("Confidential Data", fix_key("A1B2C3D4E5F60708", 16), "AES", "CBC")
h = sha256_hex(ct)
verify_hash(ct, h)                 # PASS
verify_hash(tamper(ct, 5), h)      # FAIL -> DO NOT DECRYPT
```

### Performance + collision test: MD5 / SHA-1 / SHA-256 `[LAB L5.3]`
```python
# NEEDS: `import hashlib, random, string, time`
import string
data = ["".join(random.choices(string.ascii_letters, k=random.randint(10, 40)))
        for _ in range(100)]                       # 50-100 random strings

for algo in ("md5", "sha1", "sha256"):
    t0 = time.perf_counter()
    hs = [hashlib.new(algo, s.encode()).hexdigest() for s in data]
    t1 = time.perf_counter()
    seen, coll = {}, 0
    for s, h in zip(data, hs):
        if h in seen and seen[h] != s: coll += 1
        seen[h] = s
    print(f"{algo:<7} {(t1-t0)*1000:8.4f} ms  collisions={coll}")
```

---

# 7. LAB 6 — DIGITAL SIGNATURES

```python
# NEEDS: nothing. Paste before any signature block.
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
```

## RSA sign / verify (SHA-256 + RSA) `[LAB L6] [PYQ P1, P3]`
```python
# NEEDS: pkcs1_15, SHA256 (imports above)  +  S (sec 1)
def rsa_sign(data, priv):
    return pkcs1_15.new(priv).sign(SHA256.new(S(data)))     # hashes internally

def rsa_verify(data, sig, pub):
    try:
        pkcs1_15.new(pub).verify(SHA256.new(S(data)), sig); return True
    except (ValueError, TypeError):
        return False                                        # MUST catch - it raises
```
If the question literally says *"sign the SHA-256 hash value"*, sign the hex digest string — same call, different input:
```python
# NEEDS: sha256_hex (sec 6)  +  rsa_sign, rsa_verify (above)
h   = sha256_hex(ct)                 # store this
sig = rsa_sign(h, priv)              # sign the hash string
ok  = rsa_verify(h, sig, pub)
```

### Tampered message → invalid signature (demo block)
```python
# NEEDS: rsa_keys (sec 4)  +  rsa_sign, rsa_verify (above)
priv, pub = rsa_keys(2048)
msg = b"Transfer 1000 to Bob"
sig = rsa_sign(msg, priv)
print("original :", rsa_verify(msg, sig, pub))               # True
print("tampered :", rsa_verify(b"Transfer 9000 to Bob", sig, pub))  # False
print("wrong key:", rsa_verify(msg, sig, rsa_keys(2048)[1])) # False
```

## ElGamal signature — pure Python `[LAB L6 Ex1] [PYQ P4 — REQUIRED]`
> Not RSA. Signature = `(r, s)`, verification uses `g^H == y^r * r^s mod p`.
```python
# NEEDS: sha256_hex (sec 6), getPrime, GCD (sec 4 imports), `import random`
def egs_keygen(bits=256):
    p = getPrime(bits); g = 2
    x = random.randrange(2, p - 2); y = pow(g, x, p)
    return (p, g, y), x                                     # public, private

def egs_sign(data, p, g, x):
    H = int(sha256_hex(data), 16) % (p - 1)
    while True:
        k = random.randrange(2, p - 2)
        if GCD(k, p - 1) == 1: break
    r = pow(g, k, p)
    s = ((H - x * r) * pow(k, -1, p - 1)) % (p - 1)
    if s == 0: return egs_sign(data, p, g, x)
    return r, s

def egs_verify(data, sig, p, g, y):
    r, s = sig
    if not (0 < r < p): return False
    H = int(sha256_hex(data), 16) % (p - 1)
    return pow(g, H, p) == (pow(y, r, p) * pow(r, s, p)) % p

# demo
(pk, gk, yk), xk = egs_keygen(256)
sg = egs_sign(b"record-1", pk, gk, xk)
print(egs_verify(b"record-1", sg, pk, gk, yk))     # True
print(egs_verify(b"record-X", sg, pk, gk, yk))     # False
```

## Schnorr signature (if asked alongside ElGamal) `[LAB L6 Ex1]`
```python
# NEEDS: sha256_hex (sec 6), long_to_bytes, getPrime, isPrime (sec 4 imports), S (sec 1), `import random`
def schnorr_sign(data, p, q, g, x):
    k = random.randrange(1, q); r = pow(g, k, p)
    e = int(sha256_hex(S(data) + long_to_bytes(r)), 16) % q
    return e, (k + x * e) % q                                # (e, s)

def schnorr_verify(data, sig, p, q, g, y):
    e, s = sig
    rv = (pow(g, s, p) * pow(y, q - e, p)) % p               # y^-e
    return e == int(sha256_hex(S(data) + long_to_bytes(rv)), 16) % q

from Crypto.Util.number import isPrime
def schnorr_params(qbits=160):               # Schnorr needs q | p-1 and ord(g)=q
    q = getPrime(qbits); t = 2
    while not isPrime(q * t + 1): t += 2
    p = q * t + 1; g = 2
    while True:
        h = pow(g, (p - 1) // q, p)
        if h != 1: return p, q, h            # returns (p, q, g)
        g += 1
p, q, g = schnorr_params(160); x = random.randrange(1, q); y = pow(g, x, p)
sg = schnorr_sign(b"doc", p, q, g, x); print(schnorr_verify(b"doc", sg, p, q, g, y))
```

## CIA triad demo (RSA enc + RSA sign + SHA) `[LAB L6 final]`
```python
# NEEDS: rsa_keys, rsa_enc_long, rsa_dec_long (sec 4)  +  sha256_hex (sec 6)  +  rsa_sign, rsa_verify (sec 7)
priv, pub = rsa_keys(2048)
msg = b"Confidential board minutes"
ct  = rsa_enc_long(msg, pub)              # Confidentiality
h   = sha256_hex(ct)                      # Integrity
sig = rsa_sign(ct, priv)                  # Authenticity / non-repudiation
assert sha256_hex(ct) == h and rsa_verify(ct, sig, pub)
print(rsa_dec_long(ct, priv).decode())
```

---

# 8. HIGH-VALUE COMBINATIONS

## 8.0 ★ THE BIG TEMPLATE — one implementation, reused everywhere

```
plaintext → ENCRYPT → SHA256(ciphertext) → SIGN(hash) → store {ct,iv,hash,sig,ts}
         → verify hash → verify signature → DECRYPT ONLY IF BOTH PASS
```

```python
# NEEDS: sym_enc, sym_dec (sec 3) | sha256_hex (sec 6) | rsa_sign, rsa_verify (sec 7) | egs_sign, egs_verify (sec 7, only if sign="EG") | b64, ub64, ts (sec 1)
# ===== core_pipeline.py - the answer to P1, P2, P3, P4 =====
def secure_pack(plaintext, sym_key, signer_priv,
                alg="AES", mode="CBC", iv=None, sign="RSA", eg_pub=None, meta=None):
    """Encrypt -> hash ciphertext -> sign hash -> timestamped record (JSON-safe)."""
    iv, ct = sym_enc(plaintext, sym_key, alg, mode, iv)
    h      = sha256_hex(ct)
    if sign == "RSA":
        sig = b64(rsa_sign(ct, signer_priv))
    else:                                    # ElGamal: signer_priv = x, eg_pub = (p,g,y)
        p, g, y = eg_pub
        sig = egs_sign(ct, p, g, signer_priv)          # tuple (r, s)
    rec = {"ct": b64(ct), "iv": b64(iv), "hash": h, "sig": sig,
           "alg": alg, "mode": mode, "sign": sign, "ts": ts()}
    if meta: rec.update(meta)                          # filename, patient name, id...
    return rec

def secure_unpack(rec, sym_key, verifier_pub, decrypt=True):
    """Returns (plaintext_or_None, status_string). Never decrypts on failure."""
    ct, iv = ub64(rec["ct"]), ub64(rec["iv"])
    if sha256_hex(ct) != rec["hash"]:
        return None, "INTEGRITY FAILED - data tampered. Decryption aborted."
    if rec["sign"] == "RSA":
        ok = rsa_verify(ct, ub64(rec["sig"]), verifier_pub)
    else:
        p, g, y = verifier_pub
        ok = egs_verify(ct, tuple(rec["sig"]), p, g, y)
    if not ok:
        return None, "SIGNATURE INVALID - authenticity failed. Decryption aborted."
    if not decrypt:
        return None, "HASH OK / SIGNATURE VALID (verification only - not decrypted)"
    pt = sym_dec(ct, sym_key, rec["alg"], rec["mode"], iv)
    return pt, "HASH OK / SIGNATURE VALID. Decrypted."
```

**How the four PYQs map onto it (this is all that changes):**
```python
# NEEDS: secure_pack (above)  +  read_file (sec 1), egs_keygen (sec 7) for the P4 line
# P3 MediSecure : AES + user IV + RSA sign
rec = secure_pack(read_file("record.txt"), user_key, priv, "AES", "CBC", user_iv,
                  meta={"filename": "record.txt"})

# P4 SecureVault: DES-CBC + ElGamal signature
rec = secure_pack(record, des_key, x, "DES", "CBC", sign="EG", eg_pub=(p, g, y))

# P1 HealthSecure: RSA encryption instead of AES -> see 8.6
# P2 Hospital    : AES file + RSA-wrapped key + ElGamal auth code -> see 8.3 / 8.8
```

## 8.1 AES + SHA-256
```python
# NEEDS: sym_enc, sym_dec (sec 3)  +  sha256_hex (sec 6)  +  get_random_bytes
key = get_random_bytes(16)
iv, ct = sym_enc(msg, key, "AES", "CBC")
h = sha256_hex(ct)
# receiver:
if sha256_hex(ct) == h: pt = sym_dec(ct, key, "AES", "CBC", iv)
else: print("Integrity failed")
```

## 8.2 AES + RSA (hybrid / key wrapping) `[PYQ P2]`
```python
# NEEDS: sym_enc, sym_dec (sec 3) | rsa_enc, rsa_dec (sec 4) | b64, ub64 (sec 1) | get_random_bytes
def hybrid_enc(data, rsa_pub, ksize=16):
    key = get_random_bytes(ksize)
    iv, ct = sym_enc(data, key, "AES", "CBC")
    return {"ekey": b64(rsa_enc(key, rsa_pub)), "iv": b64(iv), "ct": b64(ct)}

def hybrid_dec(box, rsa_priv):
    key = rsa_dec(ub64(box["ekey"]), rsa_priv)
    return sym_dec(ub64(box["ct"]), key, "AES", "CBC", ub64(box["iv"])), key
```

## 8.3 AES + RSA + SHA-256
```python
# NEEDS: hybrid_enc, hybrid_dec (above)  +  sha256_hex (sec 6)  +  ub64, ts (sec 1)
box = hybrid_enc(data, pub); box["hash"] = sha256_hex(ub64(box["ct"])); box["ts"] = ts()
# receiver
assert sha256_hex(ub64(box["ct"])) == box["hash"], "INTEGRITY FAILED"
pt, aes_key = hybrid_dec(box, priv)
```

## 8.4 AES + SHA-256 + RSA signature
```python
# NEEDS: secure_pack, secure_unpack (sec 8.0)
rec = secure_pack(data, aes_key, priv)                 # 8.0
pt, status = secure_unpack(rec, aes_key, pub); print(status)
```

## 8.5 AES + RSA + SHA-256 + RSA signature (full hybrid, most complete answer)
```python
# NEEDS: sym_enc, sym_dec (sec 3) | rsa_enc, rsa_dec (sec 4) | rsa_sign, rsa_verify (sec 7) | sha256_hex (sec 6) | b64, ub64, ts (sec 1) | get_random_bytes
def full_pack(data, recv_pub, sender_priv):
    key = get_random_bytes(16)
    iv, ct = sym_enc(data, key, "AES", "CBC")
    return {"ekey": b64(rsa_enc(key, recv_pub)), "iv": b64(iv), "ct": b64(ct),
            "hash": sha256_hex(ct), "sig": b64(rsa_sign(ct, sender_priv)), "ts": ts()}

def full_unpack(box, recv_priv, sender_pub):
    ct = ub64(box["ct"])
    if sha256_hex(ct) != box["hash"]:                 return None, "INTEGRITY FAILED"
    if not rsa_verify(ct, ub64(box["sig"]), sender_pub): return None, "SIGNATURE INVALID"
    key = rsa_dec(ub64(box["ekey"]), recv_priv)
    return sym_dec(ct, key, "AES", "CBC", ub64(box["iv"])), "VERIFIED - decrypted"
```

## 8.6 RSA encrypt + SHA-256 + RSA signature (no AES) `[PYQ P1 HealthSecure]`
```python
# NEEDS: rsa_enc_long, rsa_dec_long (sec 4) | rsa_sign, rsa_verify (sec 7) | sha256_hex (sec 6) | b64, ub64, ts (sec 1) | `import json`
def rsa_pack(record: dict, pub, priv):
    data = json.dumps(record).encode()
    ct   = rsa_enc_long(data, pub)                    # chunked: record may be long
    return {"ct": b64(ct), "hash": sha256_hex(ct),
            "sig": b64(rsa_sign(ct, priv)), "ts": ts(), "id": record.get("name", "REC")}

def rsa_unpack(rec, priv, pub, decrypt=True):
    ct = ub64(rec["ct"])
    if sha256_hex(ct) != rec["hash"]:                  return None, "INTEGRITY FAILED"
    if not rsa_verify(ct, ub64(rec["sig"]), pub):      return None, "SIGNATURE INVALID"
    if not decrypt: return None, "VERIFIED (no decrypt rights)"
    return json.loads(rsa_dec_long(ct, priv)), "VERIFIED - decrypted"
```

## 8.7 File + AES + SHA
```python
# NEEDS: enc_file, dec_file (sec 3)  +  read_file, write_file (sec 1)  +  sha256_hex (sec 6)
iv, ct = enc_file("patient.txt", "patient.enc", key)
write_file("patient.hash", sha256_hex(ct))
# verify later
blob = read_file("patient.enc", True); ct2 = blob[16:]
assert sha256_hex(ct2) == read_file("patient.hash"), "FILE TAMPERED"
dec_file("patient.enc", "patient_out.txt", key)
```

## 8.8 File + AES + RSA (3 output files) `[PYQ P2 — exact shape]`
```python
# NEEDS: read_file, write_file, save_json, load_json, b64, ub64, hx (sec 1) | sym_enc, sym_dec (sec 3) | rsa_keys, rsa_enc, rsa_dec (sec 4) | eg_enc_text, eg_dec_text (sec 4) | sha256_hex, tamper (sec 6) | get_random_bytes
def p2_encrypt(src, aes_key, rsa_pub, auth_code, p, g, h):
    data   = read_file(src, binary=True)
    iv, ct = sym_enc(data, aes_key, "AES", "CBC")
    write_file("cipher.txt", b64(iv + ct))                       # 1. encrypted message
    write_file("aeskey.enc", b64(rsa_enc(aes_key, rsa_pub)))     # 2. RSA-wrapped AES key
    save_json("auth.json", eg_enc_text(auth_code, p, g, h))      # 3. ElGamal auth code
    write_file("cipher.hash", sha256_hex(ct))                    # sender-side hash
    print("Ciphertext :", b64(ct)[:60], "...")
    print("ElGamal pub: p=%d g=%d h=%d" % (p, g, h))
    print("RSA n=%d e=%d" % (rsa_pub.n, rsa_pub.e))
    return ct

def p2_decrypt(aes_key_priv, p, x, tamper_it=False):
    blob = ub64(read_file("cipher.txt")); iv, ct = blob[:16], blob[16:]
    if tamper_it: ct = tamper(ct, 3)                             # modify ONE byte
    if sha256_hex(ct) != read_file("cipher.hash"):
        print("INTEGRITY FAILED - file was tampered. Decryption ABORTED."); return
    key = rsa_dec(ub64(read_file("aeskey.enc")), aes_key_priv)
    print("Recovered AES key :", hx(key))
    print("Auth code         :", eg_dec_text(load_json("auth.json"), p, x))
    print("Plaintext         :", sym_dec(ct, key, "AES", "CBC", iv).decode())

# run (verified):
priv, pub = rsa_keys(2048); K = get_random_bytes(16)
p2_encrypt("input.txt", K, pub, "AUTH-9931", 7919, 2, 6465)
p2_decrypt(priv, 7919, 355)                    # x=355, NOT 2999 -- see ElGamal trap in sec 4
p2_decrypt(priv, 7919, 355, tamper_it=True)    # -> "INTEGRITY FAILED ... ABORTED"
```

## 8.9 RBAC + encryption
```python
# NEEDS: allow (sec 5)  +  secure_pack, secure_unpack (sec 8.0)  +  save_json (sec 1)  +  a global DB list
def create_record(role, data, key, priv):
    if not allow(role, "create"): return
    rec = secure_pack(data, key, priv); DB.append(rec); save_json("db.json", DB); return rec

def read_record(role, i, key, pub):
    if not allow(role, "view"): return
    pt, st = secure_unpack(DB[i], key, pub, decrypt=allow(role, "decrypt"))
    print(st); print(pt.decode() if pt else "")
```

## 8.10 RBAC + hashing / signature (audit-only role) `[PYQ P1 Nurse/Admin, P3 Auditor, P4 Officer]`
```python
# NEEDS: allow, audit (sec 5)  +  secure_unpack (sec 8.0)  +  ts (sec 1)  +  a global DB list
def audit_view(role, i, pub):
    """Metadata + verification only. NEVER decrypts."""
    if not allow(role, "view_meta"): return
    r = DB[i]
    print(f"ID/File : {r.get('filename', r.get('id', i))}")
    print(f"Hash    : {r['hash']}\nTimestamp: {r['ts']}")
    _, st = secure_unpack(r, None, pub, decrypt=False)      # key not needed
    print("Verification:", st, "| checked at", ts())
    audit("VERIFY", role, st)
```

## 8.11 Encryption + timestamp + JSON storage
```python
# NEEDS: load_json, save_json, ts (sec 1)
DB_FILE = "records.json"; DB = load_json(DB_FILE)

def store(rec):
    rec["ts"] = ts(); DB.append(rec); save_json(DB_FILE, DB); return len(DB) - 1

def list_records():
    for i, r in enumerate(DB):
        print(f"[{i}] {r.get('filename', r.get('id',''))} | {r['hash'][:16]}... | {r['ts']}")
```

---

# 9. SOCKET TOOLBOX

> One framing layer + one dispatch. Every variant below only changes the **payload dict**.
> Run server first (`python server.py`), then client. Localhost `127.0.0.1:5000`.

### 9.0 Shared framing (`netutil.py`) — import in BOTH scripts
```python
# NEEDS: nothing - self-contained. Paste this whole block into BOTH server.py and client.py.
import socket, struct, json
HOST, PORT = "127.0.0.1", 5000

def send_msg(sock, b):
    if isinstance(b, str): b = b.encode()
    sock.sendall(struct.pack(">I", len(b)) + b)

def recv_all(sock, n):
    d = b""
    while len(d) < n:
        p = sock.recv(n - len(d))
        if not p: raise ConnectionError("closed")
        d += p
    return d

def recv_msg(sock):
    return recv_all(sock, struct.unpack(">I", recv_all(sock, 4))[0])

send_json = lambda s, o: send_msg(s, json.dumps(o).encode())
recv_json = lambda s: json.loads(recv_msg(s).decode())

def serve(handler):                       # ONE server loop for every exercise
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT)); srv.listen(5); print(f"[SERVER] listening {HOST}:{PORT}")
    while True:
        conn, addr = srv.accept(); print("[SERVER] connected", addr)
        try: handler(conn)
        except Exception as e: print("[SERVER] error:", e)
        finally: conn.close()

def client(fn):                           # ONE client wrapper
    s = socket.socket(); s.connect((HOST, PORT))
    try: return fn(s)
    finally: s.close()
```

### 9.1 Basic client → server
```python
# NEEDS: sec 9.0 framing (serve, client, send_msg, recv_msg)
# server.py
def h(conn):
    print("Received:", recv_msg(conn).decode()); send_msg(conn, "ACK")
serve(h)

# client.py
client(lambda s: (send_msg(s, "Hello Server"), print(recv_msg(s).decode())))
```

### 9.2 Socket + SHA-256 `[LAB L5.2]`
```python
# NEEDS: sec 9.0 framing  +  sha256_hex (sec 6)
# server.py - hash what you receive, send hash back
def h(conn):
    data = recv_msg(conn)
    send_msg(conn, sha256_hex(data))
    print(f"[SERVER] {len(data)}B -> {sha256_hex(data)}")
serve(h)

# client.py - verify
def run(s):
    msg = b"Data integrity over network"
    send_msg(s, msg)
    got = recv_msg(s).decode()
    print("local :", sha256_hex(msg)); print("server:", got)
    print("INTEGRITY:", "VERIFIED" if got == sha256_hex(msg) else "CORRUPTED")
client(run)

# corruption demo: send msg but compare against sha256_hex(tamper(msg)) -> mismatch
```

### 9.3 Multipart socket (client splits, server reassembles) `[LAB L5 Add.1]`
```python
# NEEDS: sec 9.0 framing  +  sha256_hex (sec 6)
# server.py
def h(conn):
    n = int(recv_msg(conn).decode()); parts = [recv_msg(conn) for _ in range(n)]
    full = b"".join(parts)
    print(f"[SERVER] reassembled {n} parts, {len(full)}B")
    send_msg(conn, sha256_hex(full))
serve(h)

# client.py
def run(s):
    msg   = b"This long message is transmitted in multiple parts over the socket."
    size  = 16
    parts = [msg[i:i+size] for i in range(0, len(msg), size)]
    send_msg(s, str(len(parts)))
    for p in parts: send_msg(s, p)
    got = recv_msg(s).decode()
    print("parts sent:", len(parts))
    print("INTEGRITY:", "VERIFIED" if got == sha256_hex(msg) else "MISMATCH")
client(run)
```

### 9.4 File over socket
```python
# NEEDS: sec 9.0 framing  +  sha256_hex (sec 6)  +  read_file, write_file (sec 1)  +  `import os`
# server.py
def h(conn):
    meta = recv_json(conn); data = recv_msg(conn)
    write_file("recv_" + meta["name"], data)
    ok = sha256_hex(data) == meta["hash"]
    send_msg(conn, f"saved recv_{meta['name']} | integrity={'OK' if ok else 'FAIL'}")
serve(h)

# client.py
def run(s):
    path = "data.txt"; data = read_file(path, binary=True)
    send_json(s, {"name": os.path.basename(path), "size": len(data),
                  "hash": sha256_hex(data)})
    send_msg(s, data); print(recv_msg(s).decode())
client(run)
```

### 9.5 AES + socket
```python
# NEEDS: sec 9.0 framing  +  sym_enc, sym_dec (sec 3)  +  fix_key, b64, ub64 (sec 1)
KEY = fix_key("0123456789ABCDEF0123456789ABCDEF", 16)       # pre-shared

# server.py
def h(conn):
    m  = recv_json(conn)
    pt = sym_dec(ub64(m["ct"]), KEY, "AES", "CBC", ub64(m["iv"]))
    print("[SERVER] decrypted:", pt.decode()); send_msg(conn, "OK")
serve(h)

# client.py
def run(s):
    iv, ct = sym_enc("Secret over socket", KEY, "AES", "CBC")
    send_json(s, {"iv": b64(iv), "ct": b64(ct)}); print(recv_msg(s).decode())
client(run)
```

### 9.6 AES + SHA + socket (verify BEFORE decrypting)
```python
# NEEDS: sec 9.0 framing  +  sym_enc, sym_dec (sec 3)  +  sha256_hex, tamper (sec 6)  +  b64, ub64, ts (sec 1)
# server.py
def h(conn):
    m  = recv_json(conn); ct = ub64(m["ct"])
    if sha256_hex(ct) != m["hash"]:
        send_msg(conn, "INTEGRITY FAILED - not decrypted"); return
    pt = sym_dec(ct, KEY, "AES", "CBC", ub64(m["iv"]))
    send_msg(conn, "VERIFIED, decrypted: " + pt.decode())
serve(h)

# client.py  (set TAMPER=True to demonstrate failure)
TAMPER = False
def run(s):
    iv, ct = sym_enc("Integrity protected payload", KEY, "AES", "CBC")
    h_ = sha256_hex(ct)
    if TAMPER: ct = tamper(ct, 2)
    send_json(s, {"iv": b64(iv), "ct": b64(ct), "hash": h_, "ts": ts()})
    print(recv_msg(s).decode())
client(run)
```

### 9.7 AES + SHA + RSA signature + socket (full secure channel)
```python
# NEEDS: sec 9.0 framing  +  secure_pack, secure_unpack (sec 8.0) and everything they need  +  RSA, read_file (sec 1)
# ---- setup (run once, share pub.pem with server) ----
# priv, pub = rsa_keys(2048); write_file("priv.pem", priv.export_key()); ...

# server.py
PUB = RSA.import_key(read_file("pub.pem", True))
def h(conn):
    rec = recv_json(conn)
    pt, status = secure_unpack(rec, KEY, PUB)        # section 8.0 - reused as-is
    print("[SERVER]", status)
    send_json(conn, {"status": status, "verified_at": ts()})
    if pt: print("[SERVER] message:", pt.decode())
serve(h)

# client.py
PRIV = RSA.import_key(read_file("priv.pem", True))
def run(s):
    rec = secure_pack(b"Signed + encrypted payload", KEY, PRIV)
    send_json(s, rec); print(recv_json(s))
client(run)
```

**Socket gotchas:** always `SO_REUSEADDR`; start server first; kill with Ctrl+C;
if `Address already in use` change `PORT`; never assume one `recv()` returns everything — that is why framing is used.

---

# 10. SCENARIO LOOKUP TABLE

| Question says… | Go to | Block |
|---|---|---|
| "encrypt the file" / ".txt file" | §3 | `enc_file` / `dec_file` |
| "encrypt the AES key using RSA" | §8.2 | `hybrid_enc` |
| "hash the encrypted data/message" | §6 | `sha256_hex(ct)` |
| "ensure integrity" / "compare hash" | §6 | `verify_hash` |
| "tampering" / "modify one character" | §6 | `tamper` / `tamper_char` |
| "digital signature" | §7 | `rsa_sign` / `rsa_verify` |
| "ElGamal signature" | §7 | `egs_sign` / `egs_verify` |
| "authenticity" / "verify sender" | §7 | `rsa_verify` |
| "only decrypt if verified" | §8.0 | `secure_unpack` |
| "Doctor / Nurse / Admin / Patient / Auditor / Lawyer" | §5 | `PERMS` + `allow` |
| "must not decrypt / view plaintext" | §8.10 | `audit_view(..., decrypt=False)` |
| "timestamp" | §1 | `ts()` |
| "store records" / "list records" | §8.11 | `store` / `list_records` |
| "client / server" | §9.1 | `serve` / `client` |
| "multiple parts / chunks" | §9.3 | multipart |
| "send file over network" | §9.4 | file socket |
| "shared secret" / "key exchange" | §4 | Diffie–Hellman |
| "authorization code" (given p,g,h,x) | §4 | `eg_enc_text` |
| "Rabin" / "4 roots" / "p≡q≡3 mod 4" | §5 | `rabin_*` |
| "key revocation / renewal / storage" | §5 | `km_*` |
| "audit log / compliance report" | §5 | `audit` / `report` |
| "DES CBC with IV" | §3 | `sym_enc(..., "DES","CBC", iv)` |
| "CTR / nonce" | §3 | `sym_enc(..., "CTR", nonce)` |
| "compare performance / time taken" | §3, §6 | `time.perf_counter()` blocks |
| "brute force" / "known plaintext" | §2 | attack blocks |
| "CIA triad" | §7 | CIA demo |
| "p and q are small / factor n" | §4 | `factor_n` |

### GOTCHAS THAT COST MARKS (all hit while testing this codebook)

| Symptom | Cause / fix |
|---|---|
| `ValueError: Triple DES key degenerates to single DES` | Manual's 3DES key has K1=K2=K3 → use `des3_key()` (§1). |
| ElGamal decrypts to garbage, no error | `pow(g,x,p) != h`. Manual's `x=2999` is wrong for `h=6465`; real `x=355`. Always `assert pow(g,x,p)==h`. |
| Hash mismatch after writing then re-reading a text file | Windows `\n`→`\r\n` translation. Use `newline=""` (§1) or always open binary. |
| `pkcs1_15 ... verify` kills the program | It **raises** on failure — always wrap in `try/except ValueError`. |
| `ValueError: Plaintext is too long` (RSA) | OAEP max = keysize/8 − 42 B → use `rsa_enc_long` or encrypt an AES key instead. |
| `isqrt() argument must be nonnegative` | Fermat factoring must start at `ceil(sqrt(n))`. |
| `unpad` → "Padding is incorrect" | Wrong key/IV/mode, or you padded in CTR (CTR needs **no** padding). |
| `Incorrect IV length` | AES IV = 16 B, DES/3DES IV = 8 B; CTR nonce = half a block. |
| Socket receives a truncated message | One `recv()` ≠ one message → use the length-prefix framing (§9.0). |
| `Address already in use` | `SO_REUSEADDR`, or change `PORT`. |
| `TypeError: Object of type bytes is not JSON serializable` | Wrap every bytes field in `b64()` before `json.dump`. |
| ElGamal signature `(r,s)` fails after JSON reload | JSON turns the tuple into a list → `tuple(rec["sig"])` before verifying. |

---

# 11. LIKELY TWISTS (and the one-line change)

| Twist | Change |
|---|---|
| string → **file** | `data = read_file(path, binary=True)` and write output with `write_file`; rest identical. |
| one record → **multiple records** | Keep `DB = []` list of `secure_pack` dicts; index by `int(input())`; `save_json`. |
| generated key → **given key** | Replace `get_random_bytes(16)` with `fix_key(input("key: "), 16)`. |
| random IV → **user-provided IV** `[P3]` | Pass `iv=fix_key(input("IV: "), 16)` into `sym_enc`; store `b64(iv)` in the record. |
| AES → **DES/3DES** `[P4]` | `sym_enc(..., alg="DES")`; key 8 bytes, IV 8 bytes. Nothing else moves. |
| ECB → **CBC / CTR** | Change `mode=`; remember CBC/CTR need the IV/nonce stored too. |
| RSA signature → **ElGamal signature** `[P4]` | `sign="EG"`, pass `x` as private and `(p,g,y)` as public; `secure_unpack` handles both. |
| RSA encrypt whole record `[P1]` | Use `rsa_enc_long` / `rsa_dec_long` (OAEP caps at 214 B per block). |
| ciphertext tampered `[P2]` | `ct = tamper(ct, 3)` before hashing at the receiver → hash mismatch. |
| hash mismatch → **don't decrypt** | `secure_unpack` already returns `(None, "INTEGRITY FAILED")` — just print it. |
| invalid signature → **don't decrypt** | Same function; the signature branch returns before `sym_dec`. |
| add **timestamp** | `rec["ts"] = ts()` at creation and at every verification event. |
| add **role restrictions** | Wrap each handler in `if not allow(role, "action"): return`. |
| role can verify but **not decrypt** | `secure_unpack(rec, None, pub, decrypt=False)`. |
| add **JSON storage** | `save_json("db.json", DB)` / `DB = load_json("db.json")`. |
| add **socket** | Wrap the record with `send_json` / `recv_json` (§9.7) — no crypto change. |
| **split into chunks** | `[msg[i:i+n] for i in range(0,len(msg),n)]`, send count first (§9.3). |
| add **key revocation** | `km_revoke(entity)`; check `status == "ACTIVE"` before issuing keys. |
| add **compliance report** | `report()` dumps the audit log with a timestamp header. |
| "show all RSA values" `[P2]` | `print(priv.n, priv.e, priv.d, priv.p, priv.q)`. |
| **two users / sender+receiver** | Two keypairs: encrypt with *receiver's* public, sign with *sender's* private. |

---

# 12. UNIVERSAL MENU TEMPLATE

> Rename `ROLES`/`PERMS`/fields to match the question. Works for HealthSecure, MediSecure, SecureVault.

```python
# NEEDS: see the paste list in the comment on the next line.
# ===== main.py =====
# (paste sec 1 utils, sec 3 sym_enc/sym_dec, sec 4 rsa_*, sec 6 sha256_hex/tamper,
#        sec 7 rsa_sign/rsa_verify + egs_*, sec 8.0 secure_pack/secure_unpack, sec 5 allow/audit)

DB_FILE = "records.json"
DB      = load_json(DB_FILE)
PRIV, PUB = rsa_keys(2048)                      # signer keypair (Doctor / Patient / Client)
AES_KEY   = get_random_bytes(16)                # or fix_key(input("key: "), 16)

PERMS = {                                       # <-- EDIT: roles from the question
         "Doctor":  {"create", "view", "verify", "decrypt"},
         "Nurse":   {"view", "verify"},
         "Admin":   {"view_meta", "verify"},
}

def allow_silent(role, a): return a in PERMS.get(role, set())   # check without logging DENY

def do_create(role):
    if not allow(role, "create"): return
    rec_data = {                                # <-- EDIT: fields from the question
                "name":   input("Name          : "),
                "age":    input("Age           : "),
                "gender": input("Gender        : "),
                "blood":  input("Blood Group   : "),
                "diag":   input("Diagnosis     : "),
    }
    pt  = json.dumps(rec_data).encode()
    rec = secure_pack(pt, AES_KEY, PRIV, meta={"id": rec_data["name"]})
    DB.append(rec); save_json(DB_FILE, DB); audit("CREATE", role, rec["id"])
    print("\n--- STORED ---")
    print("Ciphertext:", rec["ct"][:60], "...")
    print("IV        :", rec["iv"])
    print("SHA-256   :", rec["hash"])
    print("Signature :", str(rec["sig"])[:60], "...")
    print("Timestamp :", rec["ts"])

def do_list(role):
    if not (allow_silent(role, "view") or allow_silent(role, "view_meta")):
        print("[ACCESS DENIED]"); return
    if not DB: print("(no records)"); return
    for i, r in enumerate(DB):
        print(f"[{i}] {r.get('id','REC')} | hash={r['hash'][:20]}... | {r['ts']}")
        if allow_silent(role, "view"):                # full metadata for non-audit roles
            print(f"     ct={r['ct'][:40]}... sig={str(r['sig'])[:40]}...")

def do_verify(role):
    if not allow(role, "verify"): return
    i = int(input("Record #: "))
    _, st = secure_unpack(DB[i], AES_KEY, PUB, decrypt=False)
    print(st, "| verified at", ts()); audit("VERIFY", role, f"rec{i}: {st}")

def do_decrypt(role):
    if not allow(role, "decrypt"): return          # Nurse/Admin/Auditor blocked here
    i = int(input("Record #: "))
    pt, st = secure_unpack(DB[i], AES_KEY, PUB)
    print(st); audit("DECRYPT", role, f"rec{i}: {st}")
    if pt:
        for k, v in json.loads(pt).items(): print(f"  {k:<8}: {v}")

def do_tamper(role):                                # demo integrity failure
    if not allow(role, "create"): return
    i = int(input("Record # to tamper: "))
    DB[i]["ct"] = b64(tamper(ub64(DB[i]["ct"]), 5))
    save_json(DB_FILE, DB); audit("TAMPER", role, f"rec{i}")
    print("One byte of the ciphertext modified. Now try Verify/Decrypt.")

MENU = {"1": ("Create / encrypt record", do_create),
        "2": ("List records",            do_list),
        "3": ("Verify integrity + signature", do_verify),
        "4": ("Decrypt record",          do_decrypt),
        "5": ("Tamper ciphertext (demo)", do_tamper),
        "6": ("Audit / compliance report", lambda r: report() if allow(r,"verify") else None)}

def main():
    print("Roles:", ", ".join(PERMS))
    role = input("Login as: ").strip()
    if role not in PERMS: print("Unknown role"); return
    audit("LOGIN", role)
    while True:
        print(f"\n===== MENU ({role}) =====")
        for k, (t, _) in MENU.items(): print(f" {k}. {t}")
        print(" 0. Logout")
        c = input("Choice: ").strip()
        if c == "0": audit("LOGOUT", role); break
        if c in MENU: MENU[c][1](role)
        else: print("Invalid choice")

if __name__ == "__main__":
    main()
```

---

# 13. 5-MINUTE BLOCKS (absolute minimum, no helpers)

```python
# NEEDS: nothing. These imports cover EVERY 5-minute block below, and the blocks run in order (ct, h, kp carry over).
# ---- imports ----
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib, json, socket, time, base64
from datetime import datetime
```
```python
# ---- AES ----
k, iv = get_random_bytes(16), get_random_bytes(16)
ct = AES.new(k, AES.MODE_CBC, iv).encrypt(pad(b"msg", 16))
pt = unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(ct), 16)
```
```python
# ---- DES-CBC ----
dk, div = b"A1B2C3D4", b"12345678"
ct = DES.new(dk, DES.MODE_CBC, div).encrypt(pad(b"msg", 8))
pt = unpad(DES.new(dk, DES.MODE_CBC, div).decrypt(ct), 8)
```
```python
# ---- RSA encrypt/decrypt ----
kp = RSA.generate(2048); pub = kp.publickey()
c  = PKCS1_OAEP.new(pub).encrypt(b"msg")
m  = PKCS1_OAEP.new(kp).decrypt(c)
```
```python
# ---- RSA sign/verify ----
sig = pkcs1_15.new(kp).sign(SHA256.new(ct))
try:  pkcs1_15.new(pub).verify(SHA256.new(ct), sig); ok = True
except ValueError: ok = False
```
```python
# ---- SHA-256 ----
h = hashlib.sha256(ct).hexdigest()
hf = hashlib.sha256(open("f.txt", "rb").read()).hexdigest()
```
```python
# ---- integrity check ----
print("OK" if hashlib.sha256(ct).hexdigest() == h else "TAMPERED")
```
```python
# ---- tamper ----
b = bytearray(ct); b[0] ^= 1; bad = bytes(b)
```
```python
# ---- RBAC ----
P = {"Doctor": {"enc","dec"}, "Nurse": {"view"}}
if "dec" not in P.get(role, set()): print("DENIED")
```
```python
# ---- file r/w ----
d = open("in.txt", "rb").read(); open("out.bin", "wb").write(ct)
```
```python
# ---- timestamp + JSON ----
rec = {"ct": base64.b64encode(ct).decode(), "hash": h,
       "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
json.dump([rec], open("db.json", "w"), indent=2)
```
```python
# ---- basic socket ----
# server
s = socket.socket(); s.bind(("127.0.0.1", 5000)); s.listen(1)
c, _ = s.accept(); data = c.recv(4096); c.send(b"ACK"); c.close()
# client
c = socket.socket(); c.connect(("127.0.0.1", 5000))
c.send(b"hello"); print(c.recv(4096)); c.close()
```
```python
# ---- socket + hash ----
# server: data = c.recv(65536); c.send(hashlib.sha256(data).hexdigest().encode())
# client: c.send(msg); print(c.recv(4096).decode() == hashlib.sha256(msg).hexdigest())
```

---

# 14. FINAL AUDIT

| Covered | Where |
|---|---|
| ✅ Lab 1 ciphers (additive/mult/affine/Vigenere/autokey/Playfair/Hill) + brute force, known-plaintext, transposition | §2 |
| ✅ Lab 2 AES-128/192/256, DES, 3DES, ECB/CBC/CTR/CFB/OFB, IV/nonce, file, timing | §3 |
| ✅ Lab 3 RSA (lib + textbook), ElGamal (gen + given params), DH, ECC/ECDH | §4 |
| ✅ Lab 4 Rabin, key gen/store/revoke/renew, RBAC, audit log | §5 |
| ✅ Lab 5 custom hash, MD5/SHA-1/SHA-256, file hash, compare, tamper, perf+collision | §6 |
| ✅ Lab 5 sockets: basic, +SHA, multipart, file, AES, AES+SHA, AES+SHA+sig | §9 |
| ✅ Lab 6 RSA signature, ElGamal signature, Schnorr, CIA triad | §7 |
| ✅ AES+RSA / AES+SHA / AES+RSA+SHA / SHA+signature / enc+SHA+signature | §8.1–8.6 |
| ✅ File handling, RBAC, timestamps, tampering, verify-before-decrypt | §8.7–8.11, §12 |
| ✅ All four PYQ shapes reachable from `secure_pack`/`secure_unpack` | §8.0 |

**Exam order of operations:** roles → data structure → encrypt → hash ciphertext → sign hash → store with timestamp → verify hash → verify signature → decrypt only if both pass → print everything at each step.
