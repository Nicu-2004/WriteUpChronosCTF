# Write ups

## 1. Rollback Pair

Un serviciu de semnare pentru dispecerizare de logistică de urgență a repornit dintr-un snapshot de stare stricat. S-au exportat opt înregistrări semnate (`R-6101`…`R-6108`) și cheia publică (secp256k1, SHA-256, semnătură `r || s` pe 32+32 octeți, `s` brut). Trebuie stabilit dacă cheia a fost expusă și, dacă da, recuperat scalarul.

1. Decodific fiecare `message_b64`, calculez `h = SHA-256(mesaj)`, despart semnătura în `r, s`.
2. Verific toate cele 8 semnături față de cheia publică — toate sunt valide.
3. Compar valorile `r`: `R-6103` și `R-6107` au același `r` (`821f3007…4f4a`) → același nonce `k` reutilizat.
4. Rezolv sistemul:

```text
k = (h1 − h2) / (s1 − s2)  mod n
d = (s1·k − h1) / r        mod n
```

```python
import base64, hashlib, json

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
p = 2**256 - 2**32 - 977
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def add(P, Q):
    if P is None: return Q
    if Q is None: return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0: return None
    if P == Q: l = 3*P[0]*P[0]*pow(2*P[1], -1, p) % p
    else:      l = (Q[1]-P[1]) * pow(Q[0]-P[0], -1, p) % p
    x = (l*l - P[0] - Q[0]) % p
    return x, (l*(P[0]-x) - P[1]) % p

def mul(k, P):
    R = None
    while k:
        if k & 1: R = add(R, P)
        P = add(P, P); k >>= 1
    return R

d = json.load(open("export.json"))
Q = (int(d["public_key"]["x"], 16), int(d["public_key"]["y"], 16))

recs = []
for r in d["records"]:
    h = int.from_bytes(hashlib.sha256(base64.b64decode(r["message_b64"])).digest(), "big")
    sig = bytes.fromhex(r["signature_rs_hex"])
    recs.append((r["record_id"], h, int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")))

for i in range(len(recs)):
    for j in range(i + 1, len(recs)):
        if recs[i][2] != recs[j][2]:
            continue
        _, h1, r, s1 = recs[i]
        _, h2, _, s2 = recs[j]
        for sa in (s1, n - s1):
            for sb in (s2, n - s2):
                if sa == sb: continue
                k = (h1 - h2) * pow(sa - sb, -1, n) % n
                priv = (sa * k - h1) * pow(r, -1, n) % n
                if mul(priv, G) == Q:
                    print(recs[i][0], recs[j][0], "CSCTF{%064x}" % priv)
```

5. Confirm: `d·G` == cheia publică dată.

**Flag:** `CSCTF{3b5789e468dadf358d375bb08dcd19b977c5715364a709326b43a35b0d5eaab1}`

---

## 2. Night Clerk

Un funcționar ostil a folosit un terminal de depozit pentru a ascunde un mesaj de coordonare înainte de izolare. Singura dovadă e imaginea stick-ului, `terminal.dd` (8.388.608 octeți).

1. Extrag fișierul `.docx` din imagine (de pe partiția FAT a stick-ului; `fls`/`icat` din The Sleuth Kit, sau `binwalk -e`, inclusiv fișiere șterse) și despachetez `word/document.xml`.
2. Documentul e un redline (Track Changes). Paragraful vizibil (`Shift summary clean. Nothing unusual at the desk.`) e momeală.
3. Al doilea paragraf are o ștergere urmărită și, de același autor (M. Keene), o inserție urmărită 11 secunde mai târziu:

```xml
<w:ins w:id="2" w:author="M. Keene" w:date="2026-04-03T02:14:11Z">
  <w:r><w:t>7a6a7a6d7f4251505d664a525c4e664b5c5d5550575c44</w:t></w:r>
</w:ins>
```

4. Hex-decodific inserția → 23 octeți ciphertext.
5. Cheia XOR e un singur octet (diferența NTP−EXIF în secunde, exhibite nefurnizate), așa că verific toate cele 256 valori:

```python
c = bytes.fromhex("7a6a7a6d7f4251505d664a525c4e664b5c5d5550575c44")
for k in range(256):
    t = bytes(b ^ k for b in c)
    if t.startswith(b"CSCTF{") and t.endswith(b"}"):
        print(k, t.decode())
# 57 (0x39) -> CSCTF{hid_skew_redline}
```

**Flag:** `CSCTF{hid_skew_redline}`

---

## 3. Operation Dawn: Relay Snapshot

O intruziune ostilă a scos din funcțiune releul militar al unei țări fictive; echipele de răspuns au făcut un snapshot al memoriei de proces în timp ce recuperau un ordin standard. Atașament: `relay.core`, ELF core Linux x86-64, 586.928 octeți.

1. `strings -a -t x relay.core | grep -E 'CSCTF|...'` scoate la iveală fragmente mici de text în heap (`hard_`, `e_orc`, `CSCTF`, `{20_`, `dock`, `_mov`, `elm_`, `grove`, `_dus`, `k_866`, `59c}`), plus momeli (`burn_it`, `fall_back`, `regroup_`, `relieve_`…). Un șir lung concatenat la offset `0x8bbec` e doar o copie secundară, ordinea lui e înșelătoare.
2. `xxd` pe zona din jurul fragmentelor arată o structură repetată de 0x30 octeți per nod: `[pointer 8B][lungime 4B][text]` — listă înlănțuită de string-uri în heap-ul unui proces Python 3.12.
3. Urmăresc pointerii, nu adresele din fișier: `CSCTF` → `{20_` → `dock` → `_mov` → `e_orc` → `hard_` → `elm_` → `grove` → `_dus` → `k_866` → `59c}`. Restul nodurilor sunt momeli (pointer nul sau pointează doar între ele).
4. Confirm fiecare legătură prin `xxd` pe nodul respectiv (pointerul din octeții 8-15 trebuie să indice exact offsetul nodului următor).

**Flag:** `CSCTF{20_dock_move_orchard_elm_grove_dusk_86659c}`

---

## 4. Operation Dawn: The Burnt Server

O forță ostilă a distrus arhiva de logistică spitalicească a unei țări fictive. Au supraviețuit doi membri de stocare dintr-un RAID 5 pe 3 discuri; dovada salvată e în `server-remains.tar` (4.198.400 octeți: `disk0.img`, `disk2.img`, `SALVAGE.txt`). Trebuie recuperat registrul de mișcare al trenurilor.

1. `SALVAGE.txt` confirmă: discul din mijloc (`disk1.img`) distrus, parametrii RAID (chunk size, layout) nesalvați.
2. Reconstrucția discului lipsă prin paritate XOR: `D1 = D0 ⊕ D2`.
3. Brute-force pe layout: testez chunk size din `{512, 1024, 2048, 4096, 8192, 16384, 32768, 65536}` și layout din `{left-asymmetric, left-symmetric, right-asymmetric, right-symmetric}`.
4. Pentru fiecare combinație, reasamblez fluxul eliminând blocul de paritate din fiecare stripe și caut antetul magic GZIP (`\x1f\x8b\x08`):

```python
import gzip

with open("disk0.img", "rb") as f: d0 = f.read()
with open("disk2.img", "rb") as f: d2 = f.read()
d1 = bytes(a ^ b for a, b in zip(d0, d2))

disks = [d0, d1, d2]
disk_len = min(len(d) for d in disks)

chunk_sizes = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
layouts = ["left-asymmetric", "left-symmetric", "right-asymmetric", "right-symmetric"]

def assemble(chunk_size, layout):
    out = bytearray()
    for stripe in range(disk_len // chunk_size):
        p_disk = (2 - stripe % 3) if "left" in layout else (stripe % 3)
        data_disks = [i for i in range(3) if i != p_disk]
        if "symmetric" in layout and stripe % 2 == 1:
            data_disks.reverse()
        for i in data_disks:
            out.extend(disks[i][stripe*chunk_size:(stripe+1)*chunk_size])
    return bytes(out)

for cs in chunk_sizes:
    for lay in layouts:
        blob = assemble(cs, lay)
        pos = blob.find(b"\x1f\x8b\x08")
        while pos != -1:
            try:
                data = gzip.decompress(blob[pos:])
                open("RAIN_decompressed.txt", "wb").write(data)
                raise SystemExit(f"layout={lay} chunk={cs}")
            except OSError:
                pos = blob.find(b"\x1f\x8b\x08", pos + 1)
```

5. Combinația corectă dezarhivează complet `RAIN_decompressed.txt` — registrul de mișcare al trenurilor. Linia **0942** conține ordinul de mișcare cu flag-ul.

**Flag:** `CSCTF{04_flint_arc_eastward_relay_6aa299}`

---

## 5. Hard Landing

O consolă de siguranță de zbor (SENTINEL FLIGHT-SAFETY CONSOLE) a acceptat comenzi distructive de la o stație pe care administratorul ei n-a folosit-o. Trebuie recuperat materialul de sesiune al administratorului și emisă comanda de recuperare documentată, cu o semnătură validă proaspătă — consola live întoarce codul de recuperare doar după ce autentifică acea comandă.

1. Jurnalul consolei arată cronologia: login legitim `operator` (11:20), login legitim `administrator` (11:22), apoi de la `192.0.2.14` (stație neautorizată) comenzile `DISABLE_SAFETY_LINK`, `DIVERT_FROM_CORRIDOR`, `SUPPRESS_RECOVERY` (11:23), urmate de `AIRCRAFT_LINK_LOST` pentru N17.
2. `tshark -r console.pcapng -Y "http" -T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e http.response.code` — vedere de ansamblu asupra traficului HTTP.
3. `tshark -r console.pcapng -Y "frame.number in {24,26,34,44}" -T fields -e frame.number -e ip.src -e ip.dst -e http.file_data` — extrag și decodific payload-urile hex:
   - cadrul 24: `{"user":"administrator"}`
   - **cadrul 26 (răspunsul serverului)**: `{"session":"adm-2aca3785b702d3ef824b9cb8","key":"2aca3785b702d3ef824b9cb870481e04e1179b09172a1f9da3710e6bb2a759f1","role":"administrator"}`
   - cadrul 34: `{"cmd":"STATUS","aircraft":"N17"}`
   - cadrul 44: `{"cmd":"DISABLE_SAFETY_LINK","aircraft":"N17"}`
4. `tshark -r console.pcapng -q -z follow,http,ascii,1` — reasamblez un request complet, observ headerele `X-Session`, `X-Timestamp`, `X-Signature`.
5. Semnătura e `HMAC-SHA256(key, timestamp + body)` — consistentă cu `X-Signature` observat pe cadrul 34 folosind cheia din cadrul 26 (expusă de server în clar la login, fără TLS).
6. Construiesc și semnez comanda de recuperare:

```python
import hmac, hashlib, time, requests

SESSION_ID = "adm-2aca3785b702d3ef824b9cb8"
HMAC_KEY   = "2aca3785b702d3ef824b9cb870481e04e1179b09172a1f9da3710e6bb2a759f1"
TARGET_URL = "http://192.0.2.20/api/command"
RECOVERY_COMMAND = "ENABLE_SAFETY_LINK"

body = f'{{"cmd":"{RECOVERY_COMMAND}","aircraft":"N17"}}'.encode()
ts = str(int(time.time()))
sig = hmac.new(HMAC_KEY.encode(), ts.encode() + body, hashlib.sha256).hexdigest()

headers = {
    "Host": "console.sentinel.example",
    "Content-Type": "application/json",
    "X-Session": SESSION_ID,
    "X-Timestamp": ts,
    "X-Signature": sig,
}

response = requests.post(TARGET_URL, headers=headers, data=body)
print(response.status_code, response.text)


## 6. Ground Lock

Utilitarul de mentenanță la sol pentru dronele GRIFFON-FC, folosit de un proxy Ash Army. Trebuie recuperat codul de service acceptat, prin analiză statică. Atașament: `fcunlock`, ELF Linux x86-64, 682.600 octeți.

1. `file` arată ELF x86-64 static, stripped. `strings -a -t x` scoate string-urile relevante:

```text
79058  usage: %s <service-code>
79072  ACCESS DENIED
79080  GRIFFON-FC ground-maintenance interlock released.
790b8  Maintenance token: CSCTF{%.*s}
```

2. Binarul e `EXEC` (non-PIE): VA = offset fișier + `0x400000`. Caut xref-urile acelor adrese în `objdump -d -M intel` și găsesc `main` la `0x4016da`:

```c
int main(int argc, char **argv) {
    if (argc != 2) { printf(USAGE, argv[0]); return 2; }
    if (strlen(argv[1]) != 24) { puts(ACCESS_DENIED); return 1; }

    int ok = 1;
    for (int i = 0; i < 3; i++) {
        uint64_t word = 0;
        for (int j = 0; j < 8; j++)
            word |= (uint64_t)(uint8_t)argv[1][i*8+j] << (j*8);

        uint64_t h = fmix64(word);
        if (h != expected_table[i + 4]) ok = 0;
    }

    if (!ok) { puts(ACCESS_DENIED); return 1; }
    puts("GRIFFON-FC ground-maintenance interlock released.");
    printf("Maintenance token: CSCTF{%.*s}\n", 24, argv[1]);
    return 0;
}
```

3. Funcția la `0x401655` e finalizerul `fmix64` din MurmurHash3 (constantele `0xff51afd7ed558ccd`, `0xc4ceb9fe1a85ec53`, shift 33) — compunere de XOR-shift (auto-inversă la shift ≥ 32) și înmulțiri modulo 2⁶⁴ cu constante impare (inversabile), deci complet inversabilă:

```python
mask = (1 << 64) - 1
inv_c1 = pow(0xff51afd7ed558ccd, -1, 1 << 64)
inv_c2 = pow(0xc4ceb9fe1a85ec53, -1, 1 << 64)

def unxor33(x):
    return (x ^ (x >> 33)) & mask

def inv_fmix64(h):
    h = unxor33(h)
    h = (h * inv_c2) & mask
    h = unxor33(h)
    h = (h * inv_c1) & mask
    h = unxor33(h)
    return h
```

4. Cele 3 valori țintă stau în `.rodata`, lângă constantele `fmix64` (offset `0x79040`):

```text
0x79040: 6bb8ff4618 35fd8b   -> 0x8bfd351846ffb86b
0x79048: b2e3a72a89fdf33f   -> 0x3ff3fd892aa7e3b2
0x79050: d2e039e6e7791ef6   -> 0xf61e79e7e639e0d2
```

5. Aplic `inv_fmix64` pe fiecare, convertesc în 8 octeți little-endian: `HALCYON_` + `1B5FC6D7` + `2036689A` = `HALCYON_1B5FC6D72036689A` (24 octeți).
6. Verificare prin rulare directă:

```text
$ ./fcunlock "HALCYON_1B5FC6D72036689A"
GRIFFON-FC ground-maintenance interlock released.
Maintenance token: CSCTF{HALCYON_1B5FC6D72036689A}
```

**Flag:** `CSCTF{HALCYON_1B5FC6D72036689A}`

---

## 7. Operation Dawn: Radio Recovery

Un bundle de recuperare software pentru link-ul radio de câmp al unei țări fictive; trebuie recuperat token-ul administrativ de recuperare blocat în el. Atașament: `firmware.bin`, 1.048.576 octeți.

1. Fișierul începe cu magic custom `DWFW`. Parsez header-ul (`ver`, `count`, apoi `count` intrări de `[nume 8B][offset 4B][mărime 4B][crc32 4B]`):

```python
import struct
d = open("firmware.bin", "rb").read()
magic = d[0:4]
ver, cnt = struct.unpack_from("<HH", d, 4)
off = 8
for i in range(cnt):
    name = d[off:off+8].rstrip(b"\x00")
    o, s, crc = struct.unpack_from("<III", d, off+8)
    off += 20
```

   4 segmente, toate cu CRC32 valid: `loader` (banner U-Boot SPL), `ubootenv` (mediu U-Boot redundant, 16384B), `msgcat` (catalog de mesaje text, 258B), `rootfs` (zlib compressed, 633B).

2. `ubootenv`: 2 copii a câte 8192B, fiecare `[CRC32 LE 4B][flag 1B][var=val\0...\0\0]`. Ambele CRC valide:
   - copia 1: `flag=0x06`, `ethaddr=00:11:22:33:44:55`, `recovery=legacy`
   - copia 2: `flag=0x07`, `ethaddr=3c:22:fb:4a:1d:90`, `recovery=ready`
   
   Convenția U-Boot: copia cu flag mai mare e cea activă → copia 2.
3. `msgcat` conține scriptul de init cu indiciul: `nvram get admin_token`.
4. `rootfs` are header zlib (`78 f9 ...`) cu bitul **FDICT** setat — necesită dicționar presetat. DICTID din header: `0x55d45a6c`.
5. Calculez Adler-32 al `msgcat`: `0x55d45a6c` — se potrivește exact. `msgcat` e chiar dicționarul presetat:

```python
import zlib
rootfs = d[0x4380:0x4380+633]
msgcat = d[0x4270:0x4270+258]
dobj = zlib.decompressobj(zdict=msgcat)
archive = dobj.decompress(rootfs) + dobj.flush()
```

6. Rezultatul e un archive CPIO `newc` cu un mini-rootfs. În `/etc/config/radio`:

```text
admin_token=7f71b81e5beb0c17a43e6ff1554ca42178e348509e2642f4081a9e7b7bed
```

   iar `/etc/init.d/S40admin` arată decodarea: `admin_token` (30 octeți hex) XOR-at ciclic cu `ethaddr` (6 octeți) din mediul U-Boot **activ**.
7. Decodific cu MAC-ul din copia activă:

```python
tok = bytes.fromhex("7f71b81e5beb0c17a43e6ff1554ca42178e348509e2642f4081a9e7b7bed")
mac = bytes.fromhex("3c22fb4a1d90")
flag = bytes(b ^ mac[i % 6] for i, b in enumerate(tok))
print(flag)   # b'CSCTF{05_train_kestrel_d48e1f}'
```

**Flag:** `CSCTF{05_train_kestrel_d48e1f}`
