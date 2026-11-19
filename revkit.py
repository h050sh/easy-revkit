#!/usr/bin/env python3
"""
revkit.py - universele static reverse-engineering triage tool
Auteur: Nullpath Security (Haider) / gegenereerd met Claude

Werkt op: PE (native x86/x64, .NET, PyInstaller, Rust/Go/Nim/Delphi), ELF, Mach-O,
JAR/class/APK/DEX, Python .pyc, scripts (PowerShell/JS/VBS/batch/bash/python),
ZIP/TAR/GZ archieven (recursief), PDF, Office (OLE/OOXML macro's), en onbekende blobs.

Doet ALLEEN statische analyse - de sample wordt nooit uitgevoerd.

Gebruik:
    revkit <bestand> [-o outdir] [--ghidra] [--all-strings] [--carve] [--max-depth N]
    python3 revkit.py <bestand> ...          (zonder installatie)

Installatie:
    pip install .            # verplicht: capstone pefile
    pip install ".[full]"    # + lief pyelftools dnfile oletools
    optioneel extern: upx, ilspycmd, jadx, pycdc/decompyle3, Ghidra (GHIDRA_HOME)

Licentie: MIT - zie LICENSE
"""
import argparse, base64, collections, gzip, hashlib, io, json, math, os, re
import shutil, struct, subprocess, sys, tarfile, tempfile, zipfile, zlib

__version__ = "1.0.0"

try:
    import capstone
except ImportError:
    capstone = None
try:
    import pefile
except ImportError:
    pefile = None
try:
    import lief
    try:
        lief.logging.disable()
    except Exception:
        pass
except ImportError:
    lief = None
try:
    import dnfile
except ImportError:
    dnfile = None

# --------------------------------------------------------------------------- output helpers
C = {"r": "\033[91m", "g": "\033[92m", "y": "\033[93m", "b": "\033[94m", "m": "\033[95m",
     "c": "\033[96m", "w": "\033[97m", "d": "\033[2m", "x": "\033[0m", "B": "\033[1m"}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C = {k: "" for k in C}


def hdr(t):
    print(f"\n{C['B']}{C['c']}== {t} =={C['x']}")


def short(s, n=160):
    s = s.replace("\n", "\\n").replace("\r", "\\r")
    return s if len(s) <= n else s[:n] + "..."


class Report:
    def __init__(self, path):
        self.path = path
        self.findings = []          # (prio, category, text, evidence)
        self.sections = collections.OrderedDict()
        self.meta = {}

    def find(self, prio, cat, text, ev=""):
        key = (cat, text)
        if any((f[1], f[2]) == key for f in self.findings):
            return
        self.findings.append((prio, cat, text, ev))

    def add(self, section, line):
        self.sections.setdefault(section, []).append(line)


PRIO_COL = {1: C["r"], 2: C["y"], 3: C["b"], 4: C["d"]}
PRIO_TXT = {1: "HIGH", 2: "MED ", 3: "INFO", 4: "LOW "}

# --------------------------------------------------------------------------- generic utils


def entropy(b):
    if not b:
        return 0.0
    cnt = collections.Counter(b)
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in cnt.values())


PRINT = set(range(0x20, 0x7f)) | {0x09}


def is_printable(b, minratio=1.0):
    if not b:
        return False
    ok = sum(1 for x in b if x in PRINT)
    return ok / len(b) >= minratio


def ascii_strings(data, minlen=5):
    for m in re.finditer(rb"[\x20-\x7e\t]{%d,}" % minlen, data):
        yield m.start(), m.group().decode("latin-1")


def utf16_strings(data, minlen=5):
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data):
        yield m.start(), m.group().decode("utf-16le", "ignore")


# string classificatie --------------------------------------------------------
STR_RULES = [
    ("private-key", 1, re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")),
    ("aws-key", 1, re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("jwt", 1, re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("github-token", 1, re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("slack-token", 1, re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google-api", 1, re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("conn-string", 1, re.compile(r"(?i)(?:server|data source|host)=[^;]{1,80};.*(?:password|pwd)=[^;]{1,80}")),
    ("cred-assign", 1, re.compile(r"(?i)\b(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|token|auth)\s*[:=]\s*['\"]?[^\s'\";]{3,}")),
    ("url-creds", 1, re.compile(r"[a-z][a-z0-9+.-]{1,10}://[^/\s:@]{1,64}:[^/\s@]{1,64}@[^\s]+")),
    ("bcrypt", 1, re.compile(r"\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}")),
    ("unix-crypt", 1, re.compile(r"\$(?:1|5|6|y|apr1)\$[^\s$]{1,16}\$[./A-Za-z0-9]{20,}")),
    ("url", 2, re.compile(r"\b(?:https?|ftp|wss?|ldaps?|smb|tcp)://[^\s'\"<>]{4,}")),
    ("ipv4", 2, re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{2,5})?\b")),
    ("unc-path", 2, re.compile(r"\\\\[A-Za-z0-9_.-]{2,}\\[^\s]{2,}")),
    ("registry", 3, re.compile(r"(?i)\b(?:HKEY_[A-Z_]+|HKLM|HKCU|SOFTWARE\\Microsoft)\\[^\s]{3,}")),
    ("email", 3, re.compile(r"\b[A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]{2,}\.[A-Za-z]{2,10}\b")),
    ("domain-user", 2, re.compile(r"\b(?!UNC\\)[A-Z][A-Z0-9-]{2,15}\\[A-Za-z][A-Za-z0-9._-]{2,20}\b")),
    ("win-path", 3, re.compile(r"\b[A-Za-z]:\\(?:[^\\\s/:*?\"<>|]+\\)*[^\\\s/:*?\"<>|]*")),
    ("cmd", 2, re.compile(r"(?i)\b(?:cmd(?:\.exe)?\s+/c|powershell(?:\.exe)?\s+-|/bin/(?:ba)?sh\b|net\s+user\s|schtasks|reg\s+add|certutil|bitsadmin|rundll32|regsvr32|mshta|wmic\s)")),
    ("auth-msg", 2, re.compile(r"(?i)\b(?:password|passwd|wachtwoord|passphrase|license|serial|activation|pin code|access (?:denied|granted)|wrong|incorrect|invalid (?:key|pass|user|cred)|login (?:failed|success)|authenticat|unauthori[sz]ed|correct|flag\{|HTB\{|THM\{|CTF\{)")),
]
HASH_RULES = [
    (32, "MD5 / NTLM (hashcat -m 0 of -m 1000)"),
    (40, "SHA1 (hashcat -m 100)"),
    (64, "SHA256 (hashcat -m 1400)"),
    (128, "SHA512 (hashcat -m 1700)"),
]
NOISE = re.compile(r"(?i)(?:\.cargo[\\/]registry|rustc[\\/][0-9a-f]{20}|/rustc/|mingw-w64|libgcc|GLIBC_|__cxa_|\.debug_|DW_[A-Z]+_|go\.(?:buildid|itab)|runtime\.|clap-rs|vcruntime|api-ms-win|Microsoft Visual C\+\+|std::|core::panicking|(?-i:NSt\d|_ZN)|GCC: \()")


def classify_string(s):
    out = []
    for name, prio, rx in STR_RULES:
        m = rx.search(s)
        if m:
            out.append((name, prio, m.group(0)))
    st = s.strip()
    if re.fullmatch(r"[0-9a-fA-F]+", st) and len(set(st.lower())) > 6 and re.search(r"[a-fA-F]", st) and re.search(r"\d", st):
        for ln, desc in HASH_RULES:
            if len(st) == ln:
                out.append(("hash", 1, f"{st}  -> {desc}"))
    if re.fullmatch(r"[A-Za-z0-9+/]{24,}={0,2}", st) and len(st) % 4 == 0:
        try:
            dec = base64.b64decode(st)
            if is_printable(dec, 0.9):
                out.append(("base64", 1, f"{st[:60]} -> {short(dec.decode('latin-1'), 120)}"))
            else:
                pass
        except Exception:
            pass
    return out


# crypto constanten -------------------------------------------------------------
CRYPTO_SIGS = {
    "MD5 init": [struct.pack("<I", 0x67452301) + struct.pack("<I", 0xefcdab89), struct.pack("<Q", 0xefcdab8967452301)],
    "MD5 T-table": [struct.pack("<I", 0xd76aa478)],
    "SHA1 init": [struct.pack("<I", 0xc3d2e1f0)],
    "SHA256 init": [struct.pack("<I", 0x6a09e667) + struct.pack("<I", 0xbb67ae85), struct.pack("<I", 0x428a2f98)],
    "SHA512 init": [struct.pack("<Q", 0x6a09e667f3bcc908)],
    "AES S-box": [bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")],
    "AES inv S-box": [bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")],
    "CRC32 table": [struct.pack("<I", 0x77073096) + struct.pack("<I", 0xee0e612c)],
    "TEA/XTEA delta": [struct.pack("<I", 0x9e3779b9), struct.pack("<I", 0x61c88647)],
    "ChaCha/Salsa": [b"expand 32-byte k", b"expand 16-byte k"],
    "Blowfish P-array": [struct.pack("<I", 0x243f6a88) + struct.pack("<I", 0x85a308d3)],
    "DES S-box": [bytes([14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7])],
    "RC4 (KSA 0..255 tabel)": [bytes(range(256))],
    "Base64 alfabet": [b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"],
}
# immediates die in code verschijnen (mov reg, imm)
CRYPTO_IMMS = {0x67452301: "MD5", 0xefcdab89: "MD5", 0x98badcfe: "MD5", 0x10325476: "MD5",
               0xefcdab8967452301: "MD5", 0x1032547698badcfe: "MD5",
               0xc3d2e1f0: "SHA1", 0x6a09e667: "SHA256", 0xbb67ae85: "SHA256",
               0x9e3779b9: "TEA", 0x61c88647: "TEA", 0xedb88320: "CRC32", 0x811c9dc5: "FNV1a",
               0x01000193: "FNV1a", 0xcbf29ce484222325: "FNV1a-64", 0x5bd1e995: "MurmurHash2"}


def scan_crypto(data, rep):
    hits = []
    for name, sigs in CRYPTO_SIGS.items():
        for sig in sigs:
            off = data.find(sig)
            if off != -1:
                hits.append((name, off))
                break
    for name, off in hits:
        rep.add("Crypto constanten", f"{name} @ file offset 0x{off:x}")
    if hits:
        rep.find(3, "crypto", "Crypto-constanten gevonden: " + ", ".join(sorted({h[0] for h in hits})))
    return hits


# carving --------------------------------------------------------------------------
CARVE_SIGS = [
    (b"MZ", "PE", lambda d, o: len(d) > o + 0x40 and d[o + struct.unpack_from("<I", d, o + 0x3c)[0]:o + struct.unpack_from("<I", d, o + 0x3c)[0] + 4] == b"PE\0\0" if len(d) > o + 0x40 and struct.unpack_from("<I", d, o + 0x3c)[0] < 0x1000 else False),
    (b"\x7fELF", "ELF", None),
    (b"PK\x03\x04", "ZIP", None),
    (b"\x1f\x8b\x08", "GZIP", None),
    (b"7z\xbc\xaf\x27\x1c", "7Z", None),
    (b"Rar!\x1a\x07", "RAR", None),
    (b"%PDF-", "PDF", None),
    (b"\x89PNG\r\n\x1a\n", "PNG", None),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE/Office", None),
    (b"SQLite format 3\0", "SQLite", None),
    (b"-----BEGIN ", "PEM", None),
    (b"dex\n03", "DEX", None),
    (b"\xca\xfe\xba\xbe", "Java class/Mach-O fat", None),
    (b"MEI\x0c\x0b\x0a\x0b\x0e", "PyInstaller cookie", None),
    (b"BSJB", ".NET metadata", None),
]


def carve(data, rep, outdir, do_extract):
    found = []
    for sig, name, check in CARVE_SIGS:
        start = 1
        cnt = 0
        while cnt < 50:
            o = data.find(sig, start)
            if o == -1:
                break
            start = o + 1
            try:
                if check and not check(data, o):
                    continue
            except Exception:
                continue
            found.append((o, name))
            cnt += 1
    found.sort()
    interesting = [f for f in found if f[1] not in ("PEM",) or True]
    for o, name in interesting[:100]:
        rep.add("Embedded data (carving)", f"0x{o:08x}  {name}")
    embedded = [f for f in found if f[1] in ("PE", "ELF", "ZIP", "GZIP", "7Z", "RAR", "OLE/Office", "SQLite", "DEX")]
    if embedded:
        rep.find(2, "embedded", f"{len(embedded)} embedded bestand(en) gevonden: " +
                 ", ".join(f"{n}@0x{o:x}" for o, n in embedded[:8]))
    if do_extract and embedded:
        cdir = os.path.join(outdir, "carved")
        os.makedirs(cdir, exist_ok=True)
        for i, (o, n) in enumerate(embedded):
            end = embedded[i + 1][0] if i + 1 < len(embedded) else len(data)
            p = os.path.join(cdir, f"{o:08x}_{n.split('/')[0].lower()}.bin")
            with open(p, "wb") as f:
                f.write(data[o:end])
        rep.add("Embedded data (carving)", f"-> geëxtraheerd naar {cdir}")
    return found


# --------------------------------------------------------------------------- format detectie
def detect(data, path):
    ext = os.path.splitext(path)[1].lower()
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        return "macho"
    if data[:4] == b"\xca\xfe\xba\xbe":
        # Java class vs Mach-O fat: class heeft major version >= 45 op offset 6
        major = struct.unpack(">H", data[6:8])[0]
        return "class" if major >= 45 and major < 100 else "macho"
    if data[:4] == b"dex\n":
        return "dex"
    if data[:4] == b"PK\x03\x04":
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            names = z.namelist()
            if "AndroidManifest.xml" in names or any(n.endswith(".dex") for n in names):
                return "apk"
            if any(n.endswith(".class") for n in names) or "META-INF/MANIFEST.MF" in names:
                return "jar"
            if "[Content_Types].xml" in names:
                return "ooxml"
        except Exception:
            pass
        return "zip"
    if data[:3] == b"\x1f\x8b\x08":
        return "gzip"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    if data[:5] == b"%PDF-":
        return "pdf"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if ext == ".pyc" or (len(data) > 16 and data[2:4] == b"\r\n" and ext in (".pyc", "")):
        if ext == ".pyc":
            return "pyc"
    sample = data[:65536]
    if sample and is_printable(sample.replace(b"\n", b" ").replace(b"\r", b" "), 0.95):
        return "script"
    if sample[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return "script"
    return "blob"


# --------------------------------------------------------------------------- native image loader
class Section:
    def __init__(self, name, va, data, execute, vsize=None):
        self.name, self.va, self.data, self.x = name, va, data, execute
        self.size = max(len(data), vsize or 0)


class Image:
    def __init__(self):
        self.arch = None          # 'x86' | 'x64' | 'arm64' | 'arm'
        self.base = 0
        self.sections = []
        self.imports = {}         # IAT/GOT slot va -> name
        self.symbols = {}         # va -> name
        self.funcs = []           # sorted (start, end, name)
        self.entry = 0
        self.lang = set()

    def read(self, va, n):
        for s in self.sections:
            if s.va <= va < s.va + len(s.data):
                o = va - s.va
                return s.data[o:o + n]
        return b""

    def in_data(self, va):
        for s in self.sections:
            if s.va <= va < s.va + s.size:
                return True
        return False

    def func_of(self, va):
        import bisect
        if not self.funcs:
            return None
        i = bisect.bisect_right(self.funcs, (va, float("inf"), "")) - 1
        if i >= 0 and self.funcs[i][0] <= va < self.funcs[i][1]:
            return self.funcs[i]
        return None


def demangle(n):
    """Rust legacy (_ZN...E) en eenvoudige Itanium C++ namen leesbaar maken."""
    m = re.match(r"^_?_ZN(.*)E$", n)
    if not m:
        return n
    body, parts, i = m.group(1), [], 0
    while i < len(body):
        mm = re.match(r"(\d+)", body[i:])
        if not mm:
            break
        ln = int(mm.group(1))
        i += len(mm.group(1))
        parts.append(body[i:i + ln])
        i += ln
    if parts and re.fullmatch(r"h[0-9a-f]{16}", parts[-1]):
        parts = parts[:-1]
    out = "::".join(parts)
    for a, b in (("$LT$", "<"), ("$GT$", ">"), ("$RF$", "&"), ("$BP$", "*"), ("$u20$", " "), ("$C$", ","), ("..", "::"), ("$u7b$", "{"), ("$u7d$", "}")):
        out = out.replace(a, b)
    return out or n


def load_pe(data, rep):
    pe = pefile.PE(data=data, fast_load=False)
    img = Image()
    m = pe.FILE_HEADER.Machine
    img.arch = {0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64", 0x1c0: "arm", 0x1c4: "arm"}.get(m, hex(m))
    img.base = pe.OPTIONAL_HEADER.ImageBase
    img.entry = img.base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    for s in pe.sections:
        name = s.Name.rstrip(b"\0").decode("latin-1", "replace")
        img.sections.append(Section(name, img.base + s.VirtualAddress, s.get_data(), bool(s.Characteristics & 0x20000000), s.Misc_VirtualSize))
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            dll = e.dll.decode("latin-1")
            for i in e.imports:
                nm = i.name.decode("latin-1") if i.name else f"ord{i.ordinal}"
                img.imports[i.address] = nm
                img.symbols[i.address] = f"{dll}!{nm}"
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if e.name:
                img.symbols[img.base + e.address] = e.name.decode("latin-1")
    # COFF symbol table (MinGW/Rust/GCC builds die niet gestript zijn)
    try:
        ptr, nsym = pe.FILE_HEADER.PointerToSymbolTable, pe.FILE_HEADER.NumberOfSymbols
        if ptr and nsym and ptr + nsym * 18 <= len(data):
            strtab = ptr + nsym * 18
            i = 0
            cnt = 0
            while i < nsym:
                e = data[ptr + i * 18: ptr + i * 18 + 18]
                nm_raw, val, secn, typ, scl, naux = struct.unpack("<8sIhHBB", e)
                if nm_raw[:4] == b"\0\0\0\0":
                    o = struct.unpack("<I", nm_raw[4:])[0]
                    end = data.find(b"\0", strtab + o)
                    nm = data[strtab + o:end].decode("latin-1")
                else:
                    nm = nm_raw.rstrip(b"\0").decode("latin-1")
                if 0 < secn <= len(pe.sections) and (typ & 0x30) == 0x20:
                    va = img.base + pe.sections[secn - 1].VirtualAddress + val
                    img.symbols[va] = demangle(nm)
                    cnt += 1
                i += 1 + naux
            if cnt:
                rep.meta["coff_symbols"] = cnt
    except Exception:
        pass
    # functiegrenzen uit .pdata (x64)
    if hasattr(pe, "DIRECTORY_ENTRY_EXCEPTION"):
        rngs = []
        for e in pe.DIRECTORY_ENTRY_EXCEPTION:
            st = e.struct
            rngs.append((img.base + st.BeginAddress, img.base + st.EndAddress))
        rngs.sort()
        # aaneengesloten chained unwind-blokken samenvoegen tot één functie
        merged = []
        for a, b in rngs:
            if merged and a <= merged[-1][1] + 0x10 and (a - merged[-1][1]) >= 0 and False:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        img.funcs = [(a, b, img.symbols.get(a, f"sub_{a:x}")) for a, b in merged]
    return pe, img


def load_lief(data, path, kind):
    if lief is None:
        return None
    b = lief.parse(list(data)) if not os.path.exists(path) else lief.parse(path)
    if b is None:
        return None
    img = Image()
    try:
        if kind == "elf":
            mach = str(b.header.machine_type)
            img.arch = "x64" if "X86_64" in mach else "x86" if ("386" in mach or "I386" in mach) else "arm64" if "AARCH64" in mach else "arm" if "ARM" in mach else mach
            for s in b.sections:
                ex = s.has(lief.ELF.Section.FLAGS.EXECINSTR)
                cont = bytes(s.content) if s.type != lief.ELF.Section.TYPE.NOBITS else b""
                if s.virtual_address:
                    img.sections.append(Section(s.name, s.virtual_address, cont, ex, s.size))
            for r in list(b.pltgot_relocations) + list(b.dynamic_relocations):
                if r.has_symbol and r.symbol.name:
                    img.imports[r.address] = r.symbol.name
                    img.symbols.setdefault(r.address, r.symbol.name)
            fr = []
            for s in b.symbols:
                try:
                    if s.is_function and s.value and s.name:
                        img.symbols[s.value] = s.name
                        if s.size:
                            fr.append((s.value, s.value + s.size, s.name))
                except Exception:
                    pass
            try:  # stripped binaries: functiegrenzen uit .eh_frame
                known = {f[0] for f in fr}
                for f in b.functions:
                    if f.size and f.address not in known:
                        fr.append((f.address, f.address + f.size, f.name or f"sub_{f.address:x}"))
            except Exception:
                pass
            img.funcs = sorted(set(fr))
            img.entry = b.entrypoint
        else:  # macho
            if isinstance(b, lief.MachO.FatBinary):
                b = b.at(0)
            cpu = str(b.header.cpu_type)
            img.arch = "x64" if "X86_64" in cpu else "x86" if "X86" in cpu else "arm64" if "ARM64" in cpu else "arm"
            for s in b.sections:
                ex = s.segment_name == "__TEXT" and s.name in ("__text", "__stubs")
                img.sections.append(Section(s.name, s.virtual_address, bytes(s.content), ex, s.size))
            fr = []
            for s in b.symbols:
                if s.value and s.name:
                    img.symbols[s.value] = s.name
            img.entry = b.entrypoint
    except Exception as e:
        print(f"{C['y']}[!] LIEF parse issue: {e}{C['x']}")
    return b, img


# --------------------------------------------------------------------------- native disassembly analyse
_FAM = {}
for _f, _alts in {"rax": "eax ax al", "rbx": "ebx bx bl", "rcx": "ecx cx cl", "rdx": "edx dx dl", "rsi": "esi si sil",
                  "rdi": "edi di dil", "rbp": "ebp bp bpl", "rsp": "esp sp spl"}.items():
    for _a in [_f] + _alts.split():
        _FAM[_a] = _f
for _n in range(8, 16):
    for _a in (f"r{_n}", f"r{_n}d", f"r{_n}w", f"r{_n}b"):
        _FAM[_a] = f"r{_n}"


LIB_FUNC = re.compile(r"^(?:_<)?(?:&?(?:mut )?)?(?:clap|clap_lex|core|alloc|std|hashbrown|indexmap|gimli|object|addr2line|miniz_oxide|adler|memchr|rustc_demangle|termcolor|os_str_bytes|strsim|textwrap|atty|once_cell|bitflags|unicode_\w+|panic_unwind|compiler_builtins|serde\w*|tokio|futures\w*|regex\w*|aho_corasick|log|libc|windows\w*|winapi\w*)\b|^(?:__mingw\w*|___w64\w*|_Z\w*|__rust\w*|rust_\w*|_Unwind\w*|_?_?gcc\w*|_[gs]et_invalid_parameter_handler|_ValidateImageBase|_FindPESection\w*|_IsNonwritableInCurrentImage|__dyn_tls\w*|__tlregdtor|_?pei386\w*)$|^_<[^>]*\bas (?:clap|core|alloc|std|hashbrown|indexmap|gimli|object)::|^(?:_?_?mingw|__acrt|__scrt|__vcrt|_?_?security_|__report_|_?_?GSHandler|_?_?C_specific)")


def is_lib_func(name):
    return bool(name) and bool(LIB_FUNC.search(name))


def fam(r):
    return _FAM.get(r, r)


STACK_REG_RX = re.compile(r"^(byte|word|dword|qword) ptr \[([re]?(?:bp|sp))(?: ([+-]) (0x[0-9a-f]+|\d+))?\], ([a-z0-9]+)$")
RIP_RX = re.compile(r"\[rip ([+-]) (0x[0-9a-f]+|\d+)\]")
IMM_RX = re.compile(r"(?<![\w\[])(0x[0-9a-f]{4,16})\b")
STACK_RX = re.compile(r"^(byte|word|dword|qword) ptr \[([re]?(?:bp|sp)) ([+-]) (0x[0-9a-f]+|\d+)\], (0x[0-9a-f]+|\d+)$")
MOV_IMM_RX = re.compile(r"^(?:r8d?|r9d?|edx|rdx|esi|rsi|ecx|rcx|qword ptr \[[^\]]+\]|dword ptr \[[^\]]+\]), (0x[0-9a-f]+|\d+)$")
CMP_FUNCS = re.compile(r"(?i)^_*(?:str(?:n)?cmp|str(?:n)?casecmp|stricmp|_?strcmpi|wcs(?:n)?cmp|_?wcsicmp|memcmp|bcmp|lstrcmp[aw]?|lstrcmpi[aw]?|CompareString[AWEx]*|strcoll|RtlCompareMemory|RtlEqualUnicodeString|RtlCompareUnicodeString|timingsafe_bcmp|CRYPTO_memcmp|.*equals?.*|.*compare.*)$")
INTERESTING_IMPORT_CATS = collections.OrderedDict([
    ("Credentials / logon", r"LogonUser|CreateProcessWithLogon|CreateProcessWithToken|CredRead|CredEnum|CredWrite|LsaRetrievePrivateData|LsaStorePrivateData|ImpersonateLoggedOnUser|DuplicateTokenEx|SetThreadToken|NetUserAdd|NetUserChangePassword|SamConnect"),
    ("Proces-executie", r"CreateProcess|WinExec|ShellExecute|system$|^_?popen|execve|execvp|execl|posix_spawn|fork$"),
    ("Crypto", r"Crypt|BCrypt|NCrypt|EVP_|AES_|RSA_|MD5|SHA\d|HMAC|DPAPI|CryptUnprotectData|CryptProtectData"),
    ("Netwerk", r"WSAStartup|^connect$|^socket$|^send$|^recv$|InternetOpen|InternetConnect|HttpSendRequest|WinHttp|URLDownloadTo|curl_|getaddrinfo|gethostbyname|SSL_"),
    ("Registry", r"^Reg(?:Open|Set|Query|Create|Delete)"),
    ("Injectie / memory", r"VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC|SetWindowsHookEx|NtMapViewOfSection|VirtualProtect|mprotect|ptrace"),
    ("Anti-debug / anti-analyse", r"IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|OutputDebugString|GetTickCount|QueryPerformanceCounter|NtSetInformationThread|FindWindow"),
    ("Services / persistence", r"CreateService|OpenSCManager|ChangeServiceConfig|StartService|RegisterServiceCtrlHandler"),
    ("Bestanden", r"CreateFile|DeleteFile|MoveFile|CopyFile|^fopen|^open$|unlink"),
    ("Dynamic loading", r"LoadLibrary|GetProcAddress|dlopen|dlsym|LdrLoadDll"),
])


def analyze_imports(img, rep):
    names = set(img.imports.values()) | {v.split("!")[-1] for v in img.symbols.values()}
    for cat, rx in INTERESTING_IMPORT_CATS.items():
        hit = sorted(n for n in names if re.search(rx, n))
        if hit:
            rep.add("Interessante imports", f"{cat}: {', '.join(hit[:25])}")
            prio = 1 if cat.startswith("Credentials") else 2 if cat in ("Proces-executie", "Injectie / memory", "Crypto") else 3
            rep.find(prio, "imports", f"{cat}: {', '.join(hit[:8])}")


def read_cstr(img, va, maxlen=512):
    raw = img.read(va, maxlen)
    if not raw:
        return None
    # utf-16?
    if len(raw) > 4 and raw[1] == 0 and raw[3] == 0 and raw[0] in PRINT:
        out = []
        for i in range(0, len(raw) - 1, 2):
            ch = raw[i] | (raw[i + 1] << 8)
            if ch == 0:
                break
            if ch > 0x7e or ch < 0x09:
                return None
            out.append(chr(ch))
        return "".join(out) if len(out) >= 2 else None
    end = raw.find(b"\0")
    s = raw if end == -1 else raw[:end]
    return s.decode("latin-1") if s else None


def native_analysis(img, rep, args):
    if capstone is None:
        rep.find(2, "tool", "capstone niet geïnstalleerd - geen disassembly analyse")
        return
    mode = {"x64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)}.get(img.arch)
    if not mode:
        rep.find(3, "native", f"Disassembly voor arch {img.arch} niet ondersteund in revkit; gebruik Ghidra")
        return
    md = capstone.Cs(*mode)
    md.skipdata = True
    xrefs = collections.defaultdict(list)     # target va -> [insn va]
    lens = {}                                 # insn va (lea) -> length immediate (Rust &str)
    thunks = {}                               # insn va -> import name (jmp [rip+x])
    calls = []                                # (insn va, target name or va)
    stack_strings = []                        # (va, string)
    crypto_insn = collections.defaultdict(set)  # func start -> {alg}
    adrp = {}
    inline_cmp = []
    total = 0
    for sec in img.sections:
        if not sec.x or not sec.data:
            continue
        prev = None
        regimm = {}
        pending_lea = []
        st_run = []    # stack string run
        for ins in md.disasm(sec.data, sec.va):
            total += 1
            mn, op = ins.mnemonic, ins.op_str
            a = ins.address
            nxt = a + ins.size
            tgt = None
            if img.arch == "x64":
                m = RIP_RX.search(op)
                if m:
                    d = int(m.group(2), 0)
                    tgt = nxt + d if m.group(1) == "+" else nxt - d
                    if mn in ("jmp", "bnd jmp") and tgt in img.imports:
                        thunks[a] = img.imports[tgt]
                        if prev is not None and prev[1].startswith("endbr"):
                            thunks[prev[0]] = img.imports[tgt]
                    elif mn == "call" and tgt in img.imports:
                        calls.append((a, img.imports[tgt]))
                    else:
                        xrefs[tgt].append(a)
                        if mn == "lea":
                            pending_lea.append((a, 4))
            elif img.arch == "arm64":
                if mn == "adrp":
                    p = op.split(", #")
                    if len(p) == 2:
                        adrp[p[0]] = int(p[1], 0)
                elif mn == "add" and op.count(",") == 2 and "#" in op:
                    r = [x.strip() for x in op.split(",")]
                    if r[1] in adrp:
                        tgt = adrp[r[1]] + int(r[2].lstrip("#"), 0)
                        xrefs[tgt].append(a)
            if img.arch in ("x86", "x64") and tgt is None:
                for mm in IMM_RX.finditer(op):
                    v = int(mm.group(1), 16)
                    if v in CRYPTO_IMMS:
                        crypto_insn[a].add(CRYPTO_IMMS[v])
                    if img.arch == "x86" and img.in_data(v):
                        if mn == "call" and False:
                            pass
                        xrefs[v].append(a)
                        if mn in ("push", "mov"):
                            pending_lea.append((a, 4))
                        if mn == "call" or mn == "jmp":
                            pass
                if img.arch == "x86" and mn in ("call", "jmp") and op.startswith("dword ptr [0x"):
                    v = int(op[len("dword ptr ["):-1], 16)
                    if v in img.imports:
                        if mn == "jmp":
                            thunks[a] = img.imports[v]
                        else:
                            calls.append((a, img.imports[v]))
            if img.arch in ("x86", "x64") and mn == "call" and op.startswith("0x"):
                calls.append((a, int(op, 16)))
            if img.arch == "arm64" and mn == "bl" and op.startswith("#0x"):
                calls.append((a, int(op[1:], 16)))
            # Rust-stijl lengte na lea
            if pending_lea and mn == "mov":
                mm = MOV_IMM_RX.match(op)
                if mm:
                    v = int(mm.group(1), 0)
                    if 0 < v <= 4096:
                        la, _ = pending_lea[0]
                        lens.setdefault(la, v)
                        pending_lea.pop(0)
            pending_lea = [(x, c - 1) for x, c in pending_lea if c - 1 > 0]
            # inline compares: movabs reg, imm  +  cmp/xor [mem], reg   of  cmp [mem], imm
            if img.arch in ("x86", "x64"):
                if mn in ("movabs", "mov"):
                    mm = re.match(r"^([a-z0-9]+), (0x[0-9a-f]+|\d+)$", op)
                    if mm:
                        regimm[fam(mm.group(1))] = (int(mm.group(2), 0), a)
                    elif tgt is not None and img.arch == "x64":
                        mm = re.match(r"^([a-z0-9]+), (byte|word|dword|qword) ptr \[rip", op)
                        if mm:
                            sz = {"byte": 1, "word": 2, "dword": 4, "qword": 8}[mm.group(2)]
                            raw = img.read(tgt, sz)
                            if len(raw) == sz:
                                regimm[fam(mm.group(1))] = (int.from_bytes(raw, "little"), a)
                    else:
                        mm = re.match(r"^([a-z0-9]+), ", op)
                        if mm and not op.split(", ")[0].endswith("]"):
                            regimm.pop(fam(mm.group(1)), None)
                if mn in ("cmp", "xor", "sub"):
                    mm = re.match(r"^(byte|word|dword|qword) ptr \[([a-z0-9]+)(?: ([+-]) (0x[0-9a-f]+|\d+))?\], (\S+)$", op)
                    if mm:
                        sz = {"byte": 1, "word": 2, "dword": 4, "qword": 8}[mm.group(1)]
                        off = int(mm.group(4), 0) * (1 if mm.group(3) == "+" else -1) if mm.group(4) else 0
                        src = mm.group(5)
                        val = regimm.get(fam(src), (None,))[0] if not src[0].isdigit() else int(src, 0)
                        if val is not None and val < (1 << (8 * sz)):
                            vb = val.to_bytes(sz, "little")
                            if sum(1 for x in vb if x in PRINT) >= max(2, sz // 2):
                                inline_cmp.append((mm.group(2), off, sz, val, a))
            prev = (a, mn)
            # stack strings: mov [rsp/rbp+off], imm   of   mov [rsp/rbp+off], reg(met bekende waarde)
            if mn == "mov":
                sm = STACK_RX.match(op)
                if sm:
                    sz = {"byte": 1, "word": 2, "dword": 4, "qword": 8}[sm.group(1)]
                    off = int(sm.group(4), 0) * (1 if sm.group(3) == "+" else -1)
                    val = int(sm.group(5), 0)
                    if val < (1 << (8 * sz)):
                        st_run.append((fam(sm.group(2)), off, sz, val, a))
                else:
                    sm = STACK_REG_RX.match(op)
                    if sm and fam(sm.group(5)) in regimm:
                        sz = {"byte": 1, "word": 2, "dword": 4, "qword": 8}[sm.group(1)]
                        off = (int(sm.group(4), 0) * (1 if sm.group(3) == "+" else -1)) if sm.group(4) else 0
                        val = regimm[fam(sm.group(5))][0] & ((1 << (8 * sz)) - 1)
                        st_run.append((fam(sm.group(2)), off, sz, val, a))
            if mn in ("call", "ret", "jmp", "bnd jmp", "bnd ret") or (mn.startswith("j") and len(st_run) > 0):
                if len(st_run) >= 2:
                    _flush_stack(st_run, stack_strings)
                st_run = []
                if mn in ("call", "ret"):
                    regimm.clear()
        if len(st_run) >= 2:
            _flush_stack(st_run, stack_strings)
    rep.meta["instructions"] = total
    # inline-compare strings bouwen: groepeer op base reg + nabijheid
    inline_strings = []
    inline_cmp.sort(key=lambda x: x[4])
    grp = []
    for it in inline_cmp:
        if grp and (it[4] - grp[-1][4] > 0x60 or it[0] != grp[-1][0]):
            _flush_stack(grp, inline_strings)
            grp = []
        grp.append(it)
    if grp:
        _flush_stack(grp, inline_strings)
    inline_strings = [(a, x) for a, x in inline_strings if not (img.func_of(a) and is_lib_func(img.func_of(a)[2]))]
    for a, sstr in inline_strings:
        rep.add("Inline compares (gecompileerde strcmp/memcmp met constanten)", f"0x{a:x}  {sstr!r}")
    # resolve calls via thunks + symbols
    resolved_calls = []
    for a, t in calls:
        if isinstance(t, int):
            name = thunks.get(t) or img.symbols.get(t) or t
        else:
            name = t
        resolved_calls.append((a, name))

    # ---- strings met xrefs ophalen
    strmap = {}
    psz = 8 if img.arch in ("x64", "arm64") else 4
    pfmt = "<Q" if psz == 8 else "<I"

    def deref_pieces(tgt):
        """tgt is een pointer(-array) in data: (ptr,len) paren zoals Rust &str / fmt::Arguments pieces."""
        out = []
        for k in range(8):
            raw = img.read(tgt + k * 2 * psz, 2 * psz)
            if len(raw) < 2 * psz:
                break
            p, ln = struct.unpack(pfmt, raw[:psz])[0], struct.unpack(pfmt, raw[psz:])[0]
            if not img.in_data(p):
                break
            if 0 < ln <= 4096:
                b = img.read(p, ln)
                if len(b) == ln and is_printable(b.replace(b"\n", b" ").replace(b"\r", b" ")):
                    out.append((p, b.decode("latin-1")))
                    continue
            if k == 0:
                s = read_cstr(img, p)
                if s and len(s) >= 3 and is_printable(s.encode("latin-1", "ignore"), 0.97):
                    out.append((p, s))
            break
        return out

    for tgt, refs in list(xrefs.items()):
        if not img.in_data(tgt):
            continue
        raw0 = img.read(tgt, 4)
        if raw0 and not is_printable(raw0[:2]):
            for p, s in deref_pieces(tgt):
                strmap.setdefault(p, (s, []))
                strmap[p][1].extend(refs)
            continue
        best = None
        for r in refs:
            if r in lens:
                raw = img.read(tgt, lens[r])
                if len(raw) == lens[r] and is_printable(raw):
                    best = raw.decode("latin-1")
                    break
        if best is None:
            s = read_cstr(img, tgt)
            if s and len(s) >= 2 and is_printable(s.encode("latin-1", "ignore"), 0.97):
                best = s
        if best:
            if tgt in strmap:
                strmap[tgt][1].extend(refs)
            else:
                strmap[tgt] = (best, list(refs))

    # ---- symbolen met interessante namen
    for va, nm in img.symbols.items():
        if re.search(r"(?i)pass|auth|login|licen|serial|check|verify|valid|secret|decrypt|key|flag|admin|token", nm) and not NOISE.search(nm) and va not in img.imports and not is_lib_func(nm):
            rep.add("Interessante functienamen", f"0x{va:x}  {nm}")

    # ---- auth-logica reconstrueren
    AUTH = re.compile(r"(?i)pass|wachtw|pwd|pin\b|licen|serial|key\b|token|secret|wrong|incorrect|denied|granted|correct|success|login|logon|auth|admin|unlock|flag|verify|welcome|access")
    AUTH_STRONG = re.compile(r"(?i)password|passwd|passphrase|wachtwoord|\bpin\b|license|licence|serial|activation|wrong|incorrect|access (?:denied|granted)|denied|granted|unlock|flag\{|htb\{|secret|credential|authenticat|log ?in (?:failed|success)|invalid (?:key|pass|user|login|cred|serial|licen|code)|correct (?:pass|key|code)|enter (?:the )?(?:pass|key|code|pin|serial|licen)")
    LIBNOISE = re.compile(r"(?i)subcommand|argument|clap|usage:|panicked|unwrap\(\)|assertion failed|index out of|overflow|utf-?8|formatter|allocation|\bstd\b|thread '|RUST_BACKTRACE|libgcc|mingw|glibc|cxa_")
    func_strings = collections.defaultdict(list)    # func key -> [(va_ref, str)]
    func_of_ref = {}
    for tgt, (s, refs) in strmap.items():
        for r in refs:
            f = img.func_of(r)
            key = (f[0], f[1], f[2]) if f else (r - 0x300, r + 0x300, f"window_{r:x}")
            func_strings[key].append((r, s, tgt))
            func_of_ref[r] = key
    func_calls = collections.defaultdict(list)
    for a, name in resolved_calls:
        f = img.func_of(a)
        if f:
            func_calls[(f[0], f[1], f[2])].append((a, name))
        else:
            for key in func_strings:
                if key[0] <= a < key[1]:
                    func_calls[key].append((a, name))
    func_crypto = collections.defaultdict(set)
    for a, algs in crypto_insn.items():
        f = img.func_of(a)
        if f:
            func_crypto[(f[0], f[1], f[2])] |= algs
        else:
            for key in func_strings:
                if key[0] <= a < key[1]:
                    func_crypto[key] |= algs
    func_stack = collections.defaultdict(list)
    for a, s in [(x, "[inline-cmp] " + y) for x, y in inline_strings] + stack_strings:
        f = img.func_of(a)
        key = (f[0], f[1], f[2]) if f else None
        if key is None:
            for k in func_strings:
                if k[0] <= a < k[1]:
                    key = k
        if key:
            func_stack[key].append((a, s))

    auth_funcs = []
    for key, items in func_strings.items():
        if is_lib_func(key[2]):
            continue
        uniq = {s for _, s, _ in items}
        noise = sum(1 for s in uniq if NOISE.search(s) or LIBNOISE.search(s))
        strong = {s for s in uniq if AUTH_STRONG.search(s) and not NOISE.search(s) and not LIBNOISE.search(s) and not re.fullmatch(r"(?:[A-Z][a-z]+){2,}", s)}
        weak = {s for s in uniq if AUTH.search(s) and not NOISE.search(s) and not LIBNOISE.search(s)} - strong
        if not strong and not (weak and func_stack.get(key)):
            continue
        cmps = [n for _, n in func_calls.get(key, []) if isinstance(n, str) and CMP_FUNCS.match(n.split("!")[-1])]
        score = len(strong) * 6 + len(weak) + min(len(cmps), 3) * 3 + len(func_crypto.get(key, ())) * 4 + len(func_stack.get(key, [])) * 2
        # library/err-handling functies met tientallen strings wegdrukken
        score -= max(0, len(uniq) - 15) // 3 + noise * 2
        if score <= 0:
            continue
        msgs = sorted(strong | weak)
        auth_funcs.append((score, key, items, msgs, cmps))
    auth_funcs.sort(key=lambda x: -x[0])

    candidates = []
    for score, key, items, msgs, cmps in auth_funcs[:8]:
        fs, fe, fname = key
        crypto = sorted(func_crypto.get(key, []))
        line = f"{fname} [0x{fs:x}-0x{fe:x}] score={score}"
        rep.add("Auth / check-logica (gereconstrueerd)", line)
        shown = sorted(items)
        shown = [x for x in shown if not re.search(r"called `(?:Result|Option)::unwrap|^src/.*\.rs$|\.cargo|/rustc/", x[1])]
        for r, s, t in shown[:30]:
            rep.add("Auth / check-logica (gereconstrueerd)", f"    0x{r:x}  ref -> 0x{t:x}  \"{short(s, 100)}\"")
        if len(shown) > 30:
            rep.add("Auth / check-logica (gereconstrueerd)", f"    ... +{len(shown) - 30} string-refs")
        for a, n in sorted(func_calls.get(key, [])):
            nn = n if isinstance(n, str) else f"sub_{n:x}"
            short_n = nn.split("!")[-1]
            relevant = CMP_FUNCS.match(short_n) or (n in img.imports.values()) or (not is_lib_func(nn) and not nn.startswith("sub_") and "drop_in_place" not in nn) \
                or re.match(r"^std::(?:io::stdio|process|env::args|fs::read)", nn)
            if relevant and not re.search(r"SRWLock|^memcpy$|^memset$|HeapAlloc|HeapFree", short_n):
                rep.add("Auth / check-logica (gereconstrueerd)", f"    0x{a:x}  call {nn}")
        if crypto:
            rep.add("Auth / check-logica (gereconstrueerd)", f"    crypto in functie: {', '.join(crypto)}  -> input wordt waarschijnlijk gehasht voor de vergelijking")
        for a, s in func_stack.get(key, []):
            rep.add("Auth / check-logica (gereconstrueerd)", f"    0x{a:x}  stack-string \"{s}\"")
        # kandidaten: alleen uit functies die echt iets vergelijken/hashen/stack-strings bouwen
        for r, s, t in items:
            if not (cmps or crypto):
                break
            for piece in _split_candidates(s, items, img, t, r, lens):
                if _is_msg(piece):
                    continue
                reason = ["staat in check-functie met auth-berichten"]
                if cmps:
                    reason.append("functie roept " + "/".join(sorted({c.split('!')[-1] for c in cmps})) + " aan")
                if crypto:
                    reason.append("functie gebruikt " + "/".join(crypto))
                sc = score + (5 if cmps else 0) + (4 if crypto else 0) - (len(piece) > 40) * 4
                if any(r - 0x40 <= ca < r for ca in crypto_insn):
                    sc += 8
                    reason.insert(0, "literal wordt direct gehasht (crypto-init vlak ervoor)")
                near_cmp = [n for ca, n in func_calls.get(key, []) if r < ca <= r + 0x80 and isinstance(n, str) and CMP_FUNCS.match(n.split("!")[-1])]
                if near_cmp:
                    sc += 8
                    reason.insert(0, f"direct daarna {near_cmp[0].split('!')[-1]}()")
                if re.fullmatch(r"(?i)administrator|admin|root|user|guest|sa|system", piece.strip()):
                    sc -= 6
                    reason.insert(0, "lijkt een USERNAME, geen wachtwoord")
                candidates.append((sc, piece, f"0x{r:x}", "; ".join(reason)))
        for a, s in func_stack.get(key, []):
            if s.startswith("[inline-cmp] "):
                candidates.append((score + 12, s[13:], f"0x{a:x}", "door compiler ge-inlinede vergelijking met constante (strcmp/memcmp weg-geoptimaliseerd)"))
            else:
                candidates.append((score + 8, s, f"0x{a:x}", "stack-string in check-functie (gebouwd om strings-dump te ontwijken)"))
        # aangeroepen functies (bv. check()) met stack/inline strings
        for ca, n in func_calls.get(key, []):
            tgt_va = n if isinstance(n, int) else next((va for va, nm in img.symbols.items() if nm == n and va not in img.imports), None)
            if tgt_va is None:
                continue
            cf = img.func_of(tgt_va)
            if not cf or cf[0] == fs or re.match(r"^(?:clap|core|std|alloc|hashbrown|indexmap|gimli|object|addr2line|memchr|rustc_demangle|std::|__)", cf[2]):
                continue
            for a, s in func_stack.get((cf[0], cf[1], cf[2]), []):
                s2 = s[13:] if s.startswith("[inline-cmp] ") else s
                callee_cmps = [m for _, m in func_calls.get((cf[0], cf[1], cf[2]), []) if isinstance(m, str) and CMP_FUNCS.match(m.split("!")[-1])]
                why = f"stack-string in {cf[2]}() die vanuit {fname} wordt aangeroepen" + (f", die {callee_cmps[0]}() doet" if callee_cmps else "")
                candidates.append((score + 10 + (6 if callee_cmps else 0), s2, f"0x{a:x}", why))

    seen = set()
    cand_sorted = []
    for c in sorted(candidates, key=lambda x: -x[0]):
        if c[1] in seen:
            continue
        seen.add(c[1])
        cand_sorted.append(c)
    for sc, piece, where, why in cand_sorted[:15]:
        rep.add("Kandidaat secrets", f"{piece!r:40}  @ {where}  ({why})")
    if cand_sorted:
        top = cand_sorted[0]
        rep.find(1, "secret", f"Meest waarschijnlijke hardcoded secret: {top[1]!r} @ {top[2]}", top[3])
        for c in cand_sorted[1:4]:
            rep.find(2, "secret", f"Kandidaat secret: {c[1]!r} @ {c[2]}", c[3])
    elif stack_strings:
        for a, s in stack_strings[:10]:
            rep.add("Kandidaat secrets", f"{s!r} @ 0x{a:x} (stack-string, buiten herkende check-functie)")

    stack_strings = [(a, x) for a, x in stack_strings if not (img.func_of(a) and is_lib_func(img.func_of(a)[2]))]
    for a, s in stack_strings[:40]:
        rep.add("Stack strings", f"0x{a:x}  {s!r}")
    if stack_strings:
        rep.find(2, "stackstr", f"{len(stack_strings)} stack-string(s) gereconstrueerd (strings die niet in `strings` output staan)")

    # alle strings-met-xref die classificeren
    for tgt, (s, refs) in strmap.items():
        if NOISE.search(s):
            continue
        for name, prio, val in classify_string(s):
            if prio <= 2:
                rep.add("Strings met code-referentie", f"[{name}] 0x{tgt:x} (refs: {', '.join(hex(r) for r in refs[:3])})  {short(s, 120)}")
    rep.meta["xref_strings"] = len(strmap)
    return cand_sorted


def _flush_stack(run, out):
    # groepeer per base register; latere writes overschrijven eerdere (zoals de CPU)
    by = collections.defaultdict(dict)
    first = {}
    for reg, off, sz, val, a in run:
        for k, byte in enumerate(val.to_bytes(sz, "little")):
            by[reg][off + k] = byte
        first.setdefault(reg, a)
    for reg, mem in by.items():
        offs = sorted(mem)
        chunk = bytearray()
        prev = None
        for o in offs:
            if prev is not None and o != prev + 1:
                _emit_stack(chunk, first[reg], out)
                chunk = bytearray()
            chunk.append(mem[o])
            prev = o
        _emit_stack(chunk, first[reg], out)


def _emit_stack(buf, a, out):
    b = bytes(buf)
    # utf-16?
    if len(b) >= 8 and b[1::2].count(0) >= len(b) // 2 - 1:
        b = b[0::2]
    b = b.split(b"\0")[0] if b"\0" in b else b
    if len(b) >= 4 and is_printable(b) and len(set(b)) > 2:
        out.append((a, b.decode("latin-1")))


AUTH_STRONG_G = re.compile(r"(?i)password|passwd|passphrase|wachtwoord|\bpin\b|license|licence|serial|activation|wrong|incorrect|access (?:denied|granted)|unlock|flag\{|htb\{|credential|authenticat|log ?in (?:failed|success)|invalid (?:key|pass|user|login|cred|serial|licen|code)")


def _is_msg(s):
    if len(s.strip()) < 4:
        return True
    if "\n" in s or s != s.strip() and len(s.strip()) > 6:
        return True
    st = s.strip()
    if len(st) < 3:
        return True
    if len(st) > 64:
        return True
    if re.search(r"(?i)enter|please|wrong|incorrect|invalid|denied|granted|failed|success|usage|error|welcome|\bthe\b|\byou\b|executing|password:|:\s*$|%[sdxuf]|\{\}|\{[0-9a-z_]*\}|\\n$|\.rs$|\.c$|\.cpp$|\.py$|^src/|^/home/|called `|panicked", st):
        return True
    if NOISE.search(st):
        return True
    return False


def _split_candidates(s, items, img, tgt, ref, lens):
    """Rust plakt literals aan elkaar - splits op basis van andere refs die in dezelfde blob vallen."""
    out = [s]
    if ref in lens:
        return out
    # probeer de blob op te knippen bij targets van andere refs in dezelfde functie
    cuts = sorted({t - tgt for _, _, t in items if 0 < t - tgt < len(s)})
    if cuts:
        parts = []
        prev = 0
        for c in cuts:
            parts.append(s[prev:c])
            prev = c
        parts.append(s[prev:])
        out = [p for p in parts if p]
    return out


# --------------------------------------------------------------------------- per-formaat analyses
def lang_hints(data, img, rep):
    h = []
    sample = data
    if b".cargo/registry" in sample or b".cargo\\registry" in sample or b"rust_panic" in sample or b"/rustc/" in sample:
        h.append("Rust")
    if b"Go build ID:" in sample or b"runtime.gopanic" in sample or b"go.buildid" in sample:
        h.append("Go")
    if b"@nim" in sample or b"nimMain" in sample or b"NimMain" in sample:
        h.append("Nim")
    if b"Borland" in sample or b"Embarcadero" in sample or b"TObject" in sample and b"SysUtils" in sample:
        h.append("Delphi")
    if b"AU3!EA06" in sample or b"AutoIt v3" in sample:
        h.append("AutoIt (gebruik autoit-ripper)")
    if b"MEI\x0c\x0b\x0a\x0b\x0e" in sample or b"pyi-runtime-tmpdir" in sample or b"_MEIPASS" in sample:
        h.append("PyInstaller")
    if b"PyRun_SimpleString" in sample and b"nuitka" in sample.lower():
        h.append("Nuitka (Python -> C, geen pyc terug te halen)")
    if b"electron" in sample.lower() and b".asar" in sample:
        h.append("Electron (zoek app.asar, uitpakken met `npx asar extract`)")
    if b"mingw" in sample.lower():
        h.append("MinGW toolchain")
    if b"GCC: (" in sample:
        h.append("GCC")
    if b"Microsoft (R) Optimizing Compiler" in sample or b"VCRUNTIME" in sample:
        h.append("MSVC")
    if b"Qt5Core" in sample or b"Qt6Core" in sample:
        h.append("Qt")
    if b"Created by GNU Go" in sample:
        h.append("gccgo")
    return h


PACKERS = {"UPX0": "UPX", "UPX1": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
           ".themida": "Themida", ".winlice": "WinLicense", ".MPRESS1": "MPRESS", ".petite": "Petite", ".nsp0": "NsPack",
           ".enigma1": "Enigma", ".boom": "Boomerang", "pebundle": "PEBundle", ".packed": "generic packer", ".perplex": "Perplex"}


def analyze_pe(data, path, rep, args, outdir, depth):
    if pefile is None:
        rep.find(2, "tool", "pefile niet geïnstalleerd")
        return
    pe, img = load_pe(data, rep)
    rep.meta["arch"] = img.arch
    rep.meta["imagebase"] = hex(img.base)
    rep.meta["entry"] = hex(img.entry)
    sub = pe.OPTIONAL_HEADER.Subsystem
    rep.meta["subsystem"] = {2: "GUI", 3: "console", 1: "native/driver"}.get(sub, str(sub))
    rep.meta["dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    try:
        import datetime
        rep.meta["compile_time"] = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        pass
    try:
        rep.meta["imphash"] = pe.get_imphash()
    except Exception:
        pass
    # secties + packing
    packed = set()
    for s in img.sections:
        e = entropy(s.data)
        flag = ""
        if s.name in PACKERS:
            packed.add(PACKERS[s.name])
        if e > 7.2 and len(s.data) > 4096:
            flag = "  <-- hoge entropie (packed/encrypted?)"
            if s.x:
                packed.add("onbekend (hoge entropie in code-sectie)")
        rep.add("Secties", f"{s.name:10} va=0x{s.va:x} raw={len(s.data):>8} vsize={s.size:>8} ent={e:4.2f} {'X' if s.x else ' '}{flag}")
    if packed:
        rep.find(1, "packer", "Packer gedetecteerd: " + ", ".join(sorted(packed)), "eerst unpacken; statische analyse is anders onbetrouwbaar")
        if "UPX" in packed and shutil.which("upx") and depth == 0:
            up = os.path.join(outdir, os.path.basename(path) + ".unpacked")
            r = subprocess.run(["upx", "-d", "-o", up, path], capture_output=True, text=True)
            if r.returncode == 0:
                rep.find(1, "packer", f"UPX automatisch uitgepakt -> {up} (wordt nu geanalyseerd)")
                analyze_file(up, outdir, args, depth + 1, rep_parent=rep)
                return
    # overlay
    try:
        ov = pe.get_overlay_data_start_offset()
        if ov and ov == pe.FILE_HEADER.PointerToSymbolTable:
            rep.add("Secties", f"overlay @ 0x{ov:x} = COFF symbol table + debug info (geen payload; functienamen ingeladen)")
        elif ov:
            rep.add("Secties", f"overlay @ 0x{ov:x} ({len(data) - ov} bytes, entropie {entropy(data[ov:ov + 1 << 20]):.2f})")
            rep.find(2, "overlay", f"Overlay van {len(data) - ov} bytes na de PE (installer/archive/config/payload?)")
    except Exception:
        pass
    # resources
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        try:
            for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                tname = str(t.name) if t.name else pefile.RESOURCE_TYPE.get(t.struct.Id, str(t.struct.Id))
                for e in t.directory.entries:
                    for l in e.directory.entries:
                        d = l.data.struct
                        raw = pe.get_data(d.OffsetToData, d.Size)
                        ent = entropy(raw)
                        rep.add("Resources", f"{tname}/{e.name or e.struct.Id} size={d.Size} ent={ent:.2f} magic={raw[:4].hex()}")
                        if tname not in ("RT_ICON", "RT_GROUP_ICON", "RT_VERSION", "RT_MANIFEST") and (d.Size > 2048 and (ent > 7.0 or raw[:2] == b"MZ")):
                            rep.find(2, "resource", f"Verdachte resource {tname}/{e.name or e.struct.Id} ({d.Size} bytes, ent {ent:.2f})")
                        if tname == "RT_VERSION":
                            pass
        except Exception:
            pass
    try:
        for fi in getattr(pe, "FileInfo", []) or []:
            for entry in fi:
                for st in getattr(entry, "StringTable", []):
                    for k, v in st.entries.items():
                        rep.add("Versie-info", f"{k.decode(errors='ignore')}: {v.decode(errors='ignore')}")
    except Exception:
        pass
    # .NET?
    clr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    if clr.VirtualAddress and clr.Size:
        rep.meta["type"] = ".NET assembly"
        analyze_dotnet(path, data, rep, outdir)
        return
    for h in lang_hints(data, img, rep):
        img.lang.add(h)
    if img.lang:
        rep.meta["language"] = ", ".join(sorted(img.lang))
    if "PyInstaller" in img.lang:
        analyze_pyinstaller(data, path, rep, outdir, args, depth)
    if any(x.startswith("Go") for x in img.lang):
        rep.find(3, "lang", "Go binary: gebruik GoReSym / redress voor functienamen en types; Ghidra 11+ heeft Go-support")
    if any(x.startswith("Rust") for x in img.lang):
        rep.find(3, "lang", "Rust binary: &str literals hebben geen NUL, ze plakken aan elkaar in .rdata; revkit splitst ze via lengte-immediates")
    analyze_imports(img, rep)
    native_analysis(img, rep, args)
    if args.ghidra:
        run_ghidra(path, rep, outdir)


def analyze_elf_macho(data, path, rep, args, outdir, depth, kind):
    res = load_lief(data, path, kind)
    if not res:
        rep.find(2, "tool", "lief niet beschikbaar of parse fout - beperkte analyse")
        return
    b, img = res
    rep.meta["arch"] = img.arch
    rep.meta["entry"] = hex(img.entry)
    if kind == "elf":
        try:
            rep.meta["pie"] = b.is_pie
            rep.meta["stripped"] = not any(True for s in b.symtab_symbols) if hasattr(b, "symtab_symbols") else None
            rep.meta["nx"] = b.has_nx
            libs = list(b.libraries)
            rep.meta["libraries"] = libs
            interp = b.interpreter if b.has_interpreter else "static"
            rep.meta["interpreter"] = interp
        except Exception:
            pass
    packed = set()
    for s in img.sections:
        e = entropy(s.data)
        rep.add("Secties", f"{s.name:20} va=0x{s.va:x} size={s.size:>8} ent={e:4.2f} {'X' if s.x else ' '}")
    if b"UPX!" in data[:4096] or b"UPX!" in data[-4096:]:
        packed.add("UPX")
    if packed:
        rep.find(1, "packer", "Packer: " + ", ".join(packed))
        if shutil.which("upx") and depth == 0:
            up = os.path.join(outdir, os.path.basename(path) + ".unpacked")
            if subprocess.run(["upx", "-d", "-o", up, path], capture_output=True).returncode == 0:
                rep.find(1, "packer", f"UPX uitgepakt -> {up}")
                analyze_file(up, outdir, args, depth + 1, rep_parent=rep)
                return
    for h in lang_hints(data, img, rep):
        img.lang.add(h)
    if img.lang:
        rep.meta["language"] = ", ".join(sorted(img.lang))
    if "PyInstaller" in img.lang:
        analyze_pyinstaller(data, path, rep, outdir, args, depth)
    analyze_imports(img, rep)
    native_analysis(img, rep, args)
    if args.ghidra:
        run_ghidra(path, rep, outdir)


# ---- .NET ------------------------------------------------------------------------
def _dn_us_heap(raw):
    out = []
    i = 1
    while i < len(raw):
        b0 = raw[i]
        if b0 & 0x80 == 0:
            ln, hl = b0, 1
        elif b0 & 0xc0 == 0x80:
            ln, hl = ((b0 & 0x3f) << 8) | raw[i + 1], 2
        else:
            ln, hl = ((b0 & 0x1f) << 24) | (raw[i + 1] << 16) | (raw[i + 2] << 8) | raw[i + 3], 4
        blob = raw[i + hl:i + hl + ln]
        if ln >= 1:
            s = blob[:-1].decode("utf-16le", "ignore") if ln % 2 == 1 else blob.decode("utf-16le", "ignore")
            out.append((i, s))
        i += hl + ln
        if ln == 0:
            pass
    return out


def analyze_dotnet(path, data, rep, outdir):
    if dnfile is None:
        rep.find(2, "tool", ".NET assembly - installeer dnfile voor diepe analyse; of decompileer met ILSpy/dnSpy")
        return
    pe = dnfile.dnPE(path) if os.path.exists(path) else dnfile.dnPE(data=data)
    net = pe.net
    if net is None:
        return
    # obfuscators
    blob = data
    obf = []
    for sig, nm in [(b"ConfusedByAttribute", "ConfuserEx"), (b"ConfuserEx", "ConfuserEx"), (b"DotfuscatorAttribute", "Dotfuscator"),
                    (b"SmartAssembly", "SmartAssembly"), (b"Babel", "Babel.NET"), (b"Eazfuscator", "Eazfuscator"),
                    (b".NET Reactor", ".NET Reactor"), (b"Xenocode", "Xenocode"), (b"CryptoObfuscator", "Crypto Obfuscator"),
                    (b"Agile.NET", "Agile.NET"), (b"ObfuscatedByGoliath", "Goliath"), (b"KoiVM", "KoiVM")]:
        if sig in blob:
            obf.append(nm)
    if obf:
        rep.find(1, "packer", ".NET obfuscator: " + ", ".join(sorted(set(obf))), "deobfusceer eerst met de4dot / de4dot-cex")
    try:
        mods = net.mdtables.Assembly
        if mods and mods.rows:
            rep.meta["assembly"] = str(mods.rows[0].Name)
    except Exception:
        pass
    # types & methods
    interesting = re.compile(r"(?i)passw|login|logon|auth|licen|serial|decrypt|secret|token|verify|admin|cred|flag|unlock|activat|checkpass|checkkey|validatekey|validatelic")
    methods = []
    try:
        for t in net.mdtables.TypeDef.rows:
            tn = f"{t.TypeNamespace}.{t.TypeName}".strip(".")
            for ml in (t.MethodList or []):
                try:
                    m = ml.row
                    methods.append((tn, str(m.Name), m))
                except Exception:
                    pass
    except Exception:
        pass
    for tn, mn, m in methods:
        if interesting.search(mn) or interesting.search(tn):
            rep.add(".NET interessante methodes", f"{tn}::{mn}")
    # user strings
    us = None
    for s in net.metadata.streams_list:
        if s.struct.Name in (b"#US", "#US"):
            us = s.__data__
    strings = _dn_us_heap(us) if us else []
    us_by_off = {o: s for o, s in strings}
    for o, s in strings:
        for name, prio, val in classify_string(s):
            rep.add(".NET strings (geclassificeerd)", f"[{name}] {short(s, 140)}")
            if prio == 1:
                rep.find(1, name, f".NET string: {short(val, 120)}")
    rep.meta["dotnet_user_strings"] = len(strings)
    # IL scan: ldstr + vergelijking binnen dezelfde methode
    memberref = {}
    try:
        for i, r in enumerate(net.mdtables.MemberRef.rows, 1):
            memberref[0x0A000000 | i] = str(r.Name)
    except Exception:
        pass
    methoddef_names = {}
    for i, (tn, mn, m) in enumerate(methods, 1):
        pass
    try:
        for i, r in enumerate(net.mdtables.MethodDef.rows, 1):
            methoddef_names[0x06000000 | i] = str(r.Name)
    except Exception:
        pass
    CMP = re.compile(r"^(?:op_Equality|op_Inequality|Equals|Compare|CompareTo|CompareOrdinal|SequenceEqual|StartsWith|EndsWith|Contains)$")
    cands = []
    for tn, mn, m in methods:
        try:
            rva = m.Rva
            if not rva:
                continue
            off = pe.get_offset_from_rva(rva)
            h = data[off]
            if h & 3 == 2:
                code = data[off + 1: off + 1 + (h >> 2)]
            else:
                csize = struct.unpack_from("<I", data, off + 4)[0]
                hsz = (struct.unpack_from("<H", data, off)[0] >> 12) * 4
                code = data[off + hsz: off + hsz + csize]
        except Exception:
            continue
        lds, cmps = [], []
        for mm in re.finditer(rb"\x72(...)\x70", code, re.S):
            tok = int.from_bytes(mm.group(1), "little")
            if tok in us_by_off:
                lds.append(us_by_off[tok])
        for mm in re.finditer(rb"[\x28\x6f](...)\x0a", code, re.S):
            tok = 0x0A000000 | int.from_bytes(mm.group(1), "little")
            nm = memberref.get(tok)
            if nm and CMP.match(nm):
                cmps.append(nm)
        if lds:
            rep.add(".NET methode-strings", f"{tn}::{mn}: " + " | ".join(repr(short(x, 60)) for x in lds[:12]))
        auth_ctx = interesting.search(mn) or interesting.search(tn) or any(AUTH_STRONG_G.search(x) for x in lds)
        if cmps and lds and auth_ctx:
            for s in lds:
                if not _is_msg(s):
                    cands.append((s, f"{tn}::{mn}", "/".join(sorted(set(cmps)))))
    seen = set()
    for s, where, c in cands:
        if s in seen:
            continue
        seen.add(s)
        rep.add("Kandidaat secrets", f"{s!r:40} in {where} (vergeleken via {c})")
    for s, where, c in cands[:4]:
        rep.find(1 if cands.index((s, where, c)) == 0 else 2, "secret", f".NET vergelijking met literal {s!r} in {where}", f"via {c}")
    # decompileren met ilspycmd
    ilspy = shutil.which("ilspycmd")
    if ilspy:
        d = os.path.join(outdir, "ilspy")
        os.makedirs(d, exist_ok=True)
        r = subprocess.run([ilspy, "-p", "-o", d, path], capture_output=True, text=True, timeout=600)
        rep.find(1 if r.returncode == 0 else 2, "decompile", f"ILSpy decompilatie -> {d}" if r.returncode == 0 else f"ILSpy faalde: {r.stderr[:200]}")
    else:
        rep.find(3, "tool", ".NET: voor volledige C# broncode -> `dotnet tool install -g ilspycmd` en run revkit opnieuw (of open in dnSpy)")


# ---- PyInstaller ------------------------------------------------------------------
PYI_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"


def marshal_strings(raw):
    """Haal strings uit marshal data zonder unmarshal (versie-onafhankelijk)."""
    out = []
    i = 0
    n = len(raw)
    while i < n - 2:
        t = raw[i] & 0x7f
        if t in (0x7a, 0x5a):  # 'z' 'Z' short ascii(interned)
            ln = raw[i + 1]
            s = raw[i + 2:i + 2 + ln]
            if ln >= 2 and len(s) == ln and is_printable(s):
                out.append(s.decode("latin-1"))
                i += 2 + ln
                continue
        elif t in (0x61, 0x41, 0x75, 0x74, 0x73):  # 'a' 'A' 'u' 't' 's'
            if i + 5 <= n:
                ln = struct.unpack_from("<I", raw, i + 1)[0]
                if 2 <= ln < 100000 and i + 5 + ln <= n:
                    s = raw[i + 5:i + 5 + ln]
                    try:
                        dec = s.decode("utf-8")
                        if all(c.isprintable() or c in "\n\r\t" for c in dec):
                            out.append(dec)
                            i += 5 + ln
                            continue
                    except Exception:
                        pass
        i += 1
    return out


def analyze_pyinstaller(data, path, rep, outdir, args, depth):
    cp = data.rfind(PYI_MAGIC)
    if cp == -1:
        rep.find(2, "pyinstaller", "PyInstaller strings maar geen cookie gevonden (mogelijk aangepaste magic)")
        return
    try:
        pkglen, toc, toclen, pyver = struct.unpack_from(">IIII", data, cp + 8)
        csize = 88 if data[cp + 24:cp + 88].strip(b"\0").startswith(b"lib") or b"python" in data[cp + 24:cp + 88].lower() else 24
        tail = len(data) - cp - csize
        ovpos = len(data) - (pkglen + tail)
        pyv = f"{pyver // 100}.{pyver % 100}" if pyver >= 100 else f"{pyver // 10}.{pyver % 10}"
        rep.meta["pyinstaller_python"] = pyv
    except Exception as e:
        rep.find(2, "pyinstaller", f"cookie parse fout: {e}")
        return
    xdir = os.path.join(outdir, "pyinstaller_extracted")
    os.makedirs(xdir, exist_ok=True)
    pos = ovpos + toc
    end = pos + toclen
    entries = []
    while pos < end:
        esz, epos, cmp_sz, ucmp_sz, flag, typ = struct.unpack_from(">IIIIBc", data, pos)
        name = data[pos + 18:pos + esz].rstrip(b"\0").decode("utf-8", "replace")
        pos += esz
        blob = data[ovpos + epos:ovpos + epos + cmp_sz]
        if flag:
            try:
                blob = zlib.decompress(blob)
            except Exception:
                pass
        entries.append((name, typ.decode(), blob))
    scripts = []
    for name, typ, blob in entries:
        safe = name.replace("..", "_").lstrip("/\\")
        p = os.path.join(xdir, safe + (".pyc" if typ == "s" else ""))
        os.makedirs(os.path.dirname(p) or xdir, exist_ok=True)
        with open(p, "wb") as f:
            f.write(blob)
        if typ == "s" and not name.startswith("pyi") and not name.startswith("pyiboot"):
            scripts.append((name, blob, p))
        if typ == "z":
            _pyz(blob, os.path.join(xdir, safe + "_extracted"), rep)
    rep.add("PyInstaller", f"Python {pyv}, {len(entries)} entries uitgepakt -> {xdir}")
    for name, blob, p in scripts:
        rep.find(1, "pyinstaller", f"Hoofdscript gevonden: {name} -> {p}")
        strs = marshal_strings(blob)
        rep.add("PyInstaller", f"[{name}] constants/names: " + " | ".join(repr(short(s, 60)) for s in strs[:80]))
        for s in strs:
            for cname, prio, val in classify_string(s):
                if prio <= 2:
                    rep.find(prio, cname, f"in {name}: {short(val, 120)}")
        # literals die naast compare-namen staan
        for s in strs:
            if not _is_msg(s) and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s) and 3 <= len(s) <= 64 and not s.startswith("<"):
                rep.add("Kandidaat secrets", f"{s!r:40} (literal in {name})")
                rep.find(2, "secret", f"Python literal in {name}: {s!r}")
        _decompile_pyc(p, rep)


def _pyz(blob, xdir, rep):
    import marshal
    if blob[:4] != b"PYZ\0":
        return
    os.makedirs(xdir, exist_ok=True)
    tocpos = struct.unpack(">I", blob[8:12])[0]
    try:
        toc = marshal.loads(blob[tocpos:])
    except Exception as e:
        rep.add("PyInstaller", f"PYZ TOC niet te unmarshallen met deze Python ({e})")
        return
    if isinstance(toc, dict):
        toc = list(toc.items())
    enc = 0
    n = 0
    for name, meta in toc:
        name = name.decode() if isinstance(name, bytes) else name
        ispkg, pos, ln = meta[:3]
        raw = blob[pos:pos + ln]
        try:
            raw = zlib.decompress(raw)
        except Exception:
            enc += 1
        with open(os.path.join(xdir, name.replace("/", "_") + ".pyc.raw"), "wb") as f:
            f.write(raw)
        n += 1
    rep.add("PyInstaller", f"PYZ: {n} modules -> {xdir}" + (f" ({enc} versleuteld - key in pyimod00_crypto_key)" if enc else ""))


def _decompile_pyc(p, rep):
    for tool in ("pycdc", "decompyle3", "uncompyle6", "pylingual"):
        exe = shutil.which(tool)
        if exe:
            r = subprocess.run([exe, p], capture_output=True, text=True, timeout=120)
            if r.stdout.strip():
                outp = p + ".py"
                with open(outp, "w") as f:
                    f.write(r.stdout)
                rep.find(1, "decompile", f"{tool} decompilatie -> {outp}")
                return
    rep.add("PyInstaller", "Geen Python decompiler gevonden (pycdc/decompyle3); alleen strings geëxtraheerd. Online: pylingual.io")


# ---- Java / Android ----------------------------------------------------------------
def class_constants(raw):
    """parse constant pool van een .class: retourneer (utf8 strings, string-literal strings, methodref namen)"""
    if raw[:4] != b"\xca\xfe\xba\xbe":
        return [], [], []
    n = struct.unpack(">H", raw[8:10])[0]
    i = 10
    utf8 = {}
    strs = []
    nat = {}
    mrefs = []
    idx = 1
    while idx < n:
        tag = raw[i]
        if tag == 1:
            ln = struct.unpack(">H", raw[i + 1:i + 3])[0]
            utf8[idx] = raw[i + 3:i + 3 + ln].decode("utf-8", "replace")
            i += 3 + ln
        elif tag in (3, 4):
            i += 5
        elif tag in (5, 6):
            i += 9
            idx += 1
        elif tag in (7, 8, 16, 19, 20):
            if tag == 8:
                strs.append(struct.unpack(">H", raw[i + 1:i + 3])[0])
            i += 3
        elif tag in (9, 10, 11, 12, 17, 18):
            if tag == 12:
                nat[idx] = struct.unpack(">H", raw[i + 1:i + 3])[0]
            if tag in (10, 11):
                mrefs.append(struct.unpack(">H", raw[i + 3:i + 5])[0])
            i += 5
        elif tag == 15:
            i += 4
        else:
            break
        idx += 1
    literal = [utf8.get(s, "") for s in strs]
    mnames = [utf8.get(nat.get(m, 0), "") for m in mrefs]
    return list(utf8.values()), literal, mnames


def analyze_java_class(raw, name, rep):
    allu, lits, mnames = class_constants(raw)
    cmp = [m for m in mnames if m in ("equals", "equalsIgnoreCase", "compareTo", "contentEquals", "matches", "isEqual", "startsWith")]
    for s in lits:
        for cname, prio, val in classify_string(s):
            rep.add("Java strings (geclassificeerd)", f"[{cname}] {name}: {short(s, 120)}")
            if prio == 1:
                rep.find(1, cname, f"{name}: {short(val, 100)}")
    if lits:
        rep.add("Java class literals", f"{name}: " + " | ".join(repr(short(x, 50)) for x in lits[:20]))
    if cmp:
        ctx = any(AUTH_STRONG_G.search(x) for x in lits)
        for s in lits:
            if not _is_msg(s) and not re.search(r"(?i)^jdbc:|://", s):
                rep.add("Kandidaat secrets", f"{s!r:40} in {name} (class gebruikt {'/'.join(sorted(set(cmp)))})")
                rep.find(1 if ctx else 3, "secret", f"Java literal {s!r} in {name} vergeleken via {'/'.join(sorted(set(cmp)))}" + (" (class bevat auth-berichten)" if ctx else ""))


def dex_strings(raw):
    n, off = struct.unpack_from("<II", raw, 0x38)
    out = []
    for k in range(min(n, 200000)):
        so = struct.unpack_from("<I", raw, off + 4 * k)[0]
        # uleb128
        p = so
        r = 0
        sh = 0
        while True:
            b = raw[p]
            p += 1
            r |= (b & 0x7f) << sh
            sh += 7
            if b < 0x80:
                break
        e = raw.find(b"\0", p)
        out.append(raw[p:e].decode("utf-8", "replace"))
    return out


def analyze_jar_apk(data, path, rep, outdir, kind):
    z = zipfile.ZipFile(io.BytesIO(data))
    names = z.namelist()
    rep.meta["entries"] = len(names)
    classes = [n for n in names if n.endswith(".class")]
    rep.add("Archief inhoud", f"{len(names)} entries, {len(classes)} classes")
    for n in names:
        if re.search(r"(?i)\.(properties|xml|json|ya?ml|conf|cfg|ini|env|txt|sql|key|pem|jks|keystore|p12)$", n) and not n.startswith("res/"):
            raw = z.read(n)
            rep.add("Config / resource bestanden", f"{n} ({len(raw)} bytes)")
            if len(raw) < 200000 and is_printable(raw[:2000].replace(b"\n", b" ").replace(b"\r", b" "), 0.9):
                for line in raw.decode("utf-8", "replace").splitlines():
                    for cname, prio, val in classify_string(line):
                        if prio <= 2:
                            rep.find(prio, cname, f"{n}: {short(line.strip(), 120)}")
    for n in classes[:3000]:
        analyze_java_class(z.read(n), n, rep)
    if kind == "apk":
        for n in names:
            if n.endswith(".dex"):
                strs = dex_strings(z.read(n))
                rep.add("DEX", f"{n}: {len(strs)} strings")
                for s in strs:
                    for cname, prio, val in classify_string(s):
                        if prio == 1:
                            rep.find(1, cname, f"{n}: {short(val, 100)}")
                        if prio <= 2:
                            rep.add("DEX strings (geclassificeerd)", f"[{cname}] {short(s, 120)}")
    jadx = shutil.which("jadx")
    if jadx:
        d = os.path.join(outdir, "jadx")
        subprocess.run([jadx, "-d", d, path], capture_output=True, text=True, timeout=900)
        rep.find(1, "decompile", f"jadx decompilatie -> {d}")
    else:
        rep.find(3, "tool", "Voor volledige Java broncode: installeer jadx (apt install jadx / github.com/skylot/jadx)")


# ---- scripts / deobfuscatie --------------------------------------------------------
def deob_layers(text, rep, depth=0, label="script", seen=None):
    if seen is None:
        seen = set()
    if depth > 6 or text in seen:
        return
    seen.add(text)
    found = []
    # PowerShell -EncodedCommand
    for m in re.finditer(r"(?i)-e(?:nc(?:odedcommand)?|c)?\s+([A-Za-z0-9+/=]{16,})", text):
        try:
            d = base64.b64decode(m.group(1)).decode("utf-16le")
            found.append(("PowerShell -EncodedCommand (UTF-16LE base64)", d))
        except Exception:
            pass
    # base64 blobs
    for m in re.finditer(r"(?:%[0-9a-fA-F]{2}){4,}|(?:\\x[0-9a-fA-F]{2}){4,}|(?:\\u00[0-9a-fA-F]{2}){4,}", text):
        h = re.sub(r"%|\\x|\\u00", "", m.group(0))
        try:
            raw = bytes.fromhex(h)
            if is_printable(raw, 0.9):
                found.append(("URL/hex-escape", raw.decode("latin-1")))
        except Exception:
            pass
    for m in re.finditer(r"[A-Za-z0-9+/]{20,}={0,2}", text):
        b = m.group(0)
        if len(b) < 40 and not (b.endswith("=") or re.search(r"[+/0-9]", b)):
            continue
        try:
            raw = base64.b64decode(b + "=" * (-len(b) % 4))
        except Exception:
            continue
        for nm, fn in (("gzip", lambda x: gzip.decompress(x)), ("raw deflate", lambda x: zlib.decompress(x, -15)), ("zlib", zlib.decompress)):
            try:
                dd = fn(raw)
                found.append((f"base64 + {nm}", dd.decode("utf-8", "replace") if is_printable(dd[:200].replace(b"\n", b" ").replace(b"\r", b" "), 0.85) else f"<{len(dd)} bytes binair, magic {dd[:4].hex()}>"))
                break
            except Exception:
                pass
        else:
            if len(raw) > 4 and raw[1:8:2] == b"\0\0\0\0":
                found.append(("base64 (UTF-16LE)", raw.decode("utf-16le", "ignore")))
            elif is_printable(raw.replace(b"\n", b" ").replace(b"\r", b" ")[:400], 0.9):
                found.append(("base64", raw.decode("latin-1")))
            elif raw[:2] == b"MZ" or raw[:4] == b"\x7fELF":
                found.append(("base64 -> EXECUTABLE", f"<{len(raw)} bytes {raw[:4]!r}>"))
            elif len(raw) >= 24:
                x = _xor_brute(raw)
                if x:
                    found.append((f"base64 + XOR key {x[0]:#04x}" if isinstance(x[0], int) else f"base64 + XOR key {x[0].hex()}", x[1]))
    # char codes
    for m in re.finditer(r"(?:\[char\]\s*\d{2,3}\s*[,+]\s*){4,}\[char\]\s*\d{2,3}", text, re.I):
        found.append(("[char] codes", "".join(chr(int(x)) for x in re.findall(r"\d{2,3}", m.group(0)))))
    for m in re.finditer(r"(?i)fromCharCode\(([\d,\s]{8,})\)", text):
        found.append(("String.fromCharCode", "".join(chr(int(x)) for x in re.findall(r"\d+", m.group(1)))))
    for m in re.finditer(r"(?i)(?:chrw?\(\d+\)\s*&\s*){3,}chrw?\(\d+\)", text):
        found.append(("VBS Chr()", "".join(chr(int(x)) for x in re.findall(r"\d+", m.group(0)))))
    for m in re.finditer(r"(?:\d{2,3}\s*,\s*){8,}\d{2,3}", text):
        nums = [int(x) for x in re.findall(r"\d+", m.group(0))]
        if all(9 <= n < 127 for n in nums):
            found.append(("decimale byte-array", "".join(map(chr, nums))))
    # hex blobs
    for m in re.finditer(r"(?:0x)?([0-9a-fA-F]{2}(?:[\s,]*(?:0x)?[0-9a-fA-F]{2}){15,})", text):
        h = re.sub(r"[\s,]|0x", "", m.group(0))
        try:
            raw = bytes.fromhex(h)
            if is_printable(raw, 0.9):
                found.append(("hex", raw.decode("latin-1")))
            elif raw[:2] == b"MZ":
                found.append(("hex -> EXECUTABLE", f"<{len(raw)} bytes>"))
            elif raw[:1] in (b"\xfc", b"\x48", b"\xe8", b"\x55") and len(raw) > 100:
                found.append(("hex (mogelijk shellcode)", f"<{len(raw)} bytes, start {raw[:8].hex()}>"))
        except Exception:
            pass
    # string concat / reversed
    joined = re.sub(r"[\"']\s*\+\s*[\"']", "", text)
    if joined != text and len(text) - len(joined) > 20:
        found.append(("string-concat samengevoegd", joined))
    for m in re.finditer(r"['\"]([^'\"]{12,})['\"]\s*\[\s*-1\s*\.\.\s*-", text):
        found.append(("reversed string", m.group(1)[::-1]))
    uniq, decs = [], set()
    for kind, dec in found:
        if dec in decs:
            continue
        decs.add(dec)
        uniq.append((kind, dec))
    found = uniq
    for kind, dec in found:
        rep.add(f"Deobfuscatie ({label})", f"{'  ' * depth}[laag {depth + 1}] {kind}: {short(dec, 400)}")
        for cname, prio, val in classify_string(dec):
            if prio <= 2:
                rep.find(prio, cname, f"na deobfuscatie ({kind}): {short(val, 140)}")
        if not dec.startswith("<"):
            deob_layers(dec, rep, depth + 1, label, seen)
    if found and depth == 0:
        rep.find(2, "deobf", f"{len(found)} geobfusceerde laag/lagen gedecodeerd (zie Deobfuscatie-sectie)")


XOR_WORDS = re.compile(rb"(?i)flag|pass|user|admin|http|key|secret|token|login|the |and |cmd|exe|dll|root|htb\{|ctf\{|this program")


def _xor_score(d):
    good = sum(1 for b in d if (65 <= b <= 90) or (97 <= b <= 122) or (48 <= b <= 57) or b in b" _-.:/=@{}\n\r,")
    if sum(1 for b in d if b in PRINT or b in (10, 13)) / max(1, len(d)) < 0.95:
        return -1
    return good + 25 * len(XOR_WORDS.findall(d))


def _xor_brute(raw):
    """single-byte en korte multi-byte (via known-plaintext) XOR."""
    best = None
    head = raw[:512]
    for k in range(1, 256):
        sc = _xor_score(bytes(b ^ k for b in head))
        if sc > 0 and (best is None or sc > best[0]):
            best = (sc, k)
    if best and best[0] >= len(head) * 0.8:
        k = best[1]
        return k, bytes(b ^ k for b in raw).decode("latin-1")
    # multi-byte: probeer key-lengtes 2..16 met per-positie beste byte
    for kl in range(2, 17):
        key = []
        for i in range(kl):
            col = head[i::kl]
            bk = max(range(256), key=lambda k: _xor_score(bytes(b ^ k for b in col)))
            key.append(bk)
        d = bytes(b ^ key[i % kl] for i, b in enumerate(raw))
        if _xor_score(d[:512]) > len(head) * 0.9 and XOR_WORDS.search(d):
            return bytes(key), d.decode("latin-1")
    return None


def analyze_script(data, path, rep):
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = data.decode("utf-16")
    else:
        text = data.decode("utf-8", "replace")
    lang = "onbekend"
    tl = text.lower()
    for nm, rx in [("PowerShell", r"\$[a-z_]+\s*=|invoke-|iex\b|-enc(?:odedcommand)?\b|\[convert\]::|powershell(?:\.exe)?\s"), ("VBScript/VBA", r"\bdim\s|createobject\(|wscript\.|sub\s+auto"),
                   ("JavaScript", r"\bvar\s|\bfunction\s*\(|eval\(|activexobject|document\."), ("Batch", r"@echo off|%~dp0|set\s+/a"),
                   ("Python", r"^import\s|^from\s.+import|def\s+\w+\(|exec\(|__import__"), ("Bash/sh", r"^#!/bin/(ba)?sh|\bcurl\s|\bwget\s|\bchmod\s"),
                   ("PHP", r"<\?php|\beval\(\$|base64_decode\("), ("HTA/HTML", r"<script|<html|<hta:")]:
        if re.search(rx, tl, re.M):
            lang = nm
            break
    rep.meta["script_language"] = lang
    for line in text.splitlines():
        for cname, prio, val in classify_string(line):
            if prio <= 2:
                rep.add("Script strings (geclassificeerd)", f"[{cname}] {short(line.strip(), 160)}")
                if prio == 1:
                    rep.find(1, cname, short(val, 140))
    danger = re.findall(r"(?i)\b(iex|invoke-expression|downloadstring|downloadfile|net\.webclient|start-process|frombase64string|eval|exec|shell\.application|wscript\.shell|activexobject|powershell|certutil|bitsadmin|curl|wget|chmod\s\+x|nc\s+-e|/dev/tcp|mshta|regsvr32|rundll32|add-mppreference|amsi|virtualalloc|system\(|passthru|shell_exec)\b", text)
    if danger:
        c = collections.Counter(d.lower() for d in danger)
        rep.find(2, "script", f"{lang}: gevaarlijke/interessante calls: " + ", ".join(f"{k}x{v}" if v > 1 else k for k, v in c.most_common(12)))
    deob_layers(text, rep, label=lang)


# ---- archives / documenten -----------------------------------------------------
def analyze_archive(data, path, rep, outdir, args, depth, kind):
    xdir = os.path.join(outdir, "archive_extracted")
    os.makedirs(xdir, exist_ok=True)
    members = []
    try:
        if kind in ("zip", "ooxml"):
            z = zipfile.ZipFile(io.BytesIO(data))
            for zi in z.infolist():
                if zi.flag_bits & 1:
                    rep.find(2, "archive", f"Versleuteld zip-lid: {zi.filename} (zip2john + john/hashcat -m 17200..17230)")
                    continue
                members.append((zi.filename, z.read(zi)))
        elif kind == "tar":
            t = tarfile.open(fileobj=io.BytesIO(data))
            for m in t.getmembers():
                if m.isfile():
                    members.append((m.name, t.extractfile(m).read()))
        elif kind == "gzip":
            raw = gzip.decompress(data)
            if len(raw) > 262 and raw[257:262] == b"ustar":
                return analyze_archive(raw, path, rep, outdir, args, depth, "tar")
            members.append((os.path.basename(path).rsplit(".", 1)[0] or "decompressed", raw))
    except Exception as e:
        rep.find(2, "archive", f"archief parse fout: {e}")
    rep.add("Archief inhoud", f"{len(members)} bestanden")
    if kind == "ooxml":
        for n, raw in members:
            if n.lower().endswith("vbaproject.bin"):
                rep.find(1, "macro", f"VBA macro project in document: {n}")
                analyze_ole(raw, n, rep)
            if n.endswith(".rels") and b"TargetMode=\"External\"" in raw:
                for m in re.findall(rb'Target="([^"]+)"[^>]*TargetMode="External"', raw):
                    rep.find(1, "external", f"Externe referentie (remote template / OLE link): {m.decode(errors='ignore')}")
    for n, raw in members[:200]:
        safe = n.replace("..", "_").lstrip("/\\")
        rep.add("Archief inhoud", f"{n} ({len(raw)} bytes, {detect(raw, n)})")
    if depth < args.max_depth:
        for n, raw in members[:60]:
            k = detect(raw, n)
            if k in ("blob",) and len(raw) < 64:
                continue
            if kind == "ooxml" and n.endswith(".xml"):
                continue
            safe = n.replace("..", "_").lstrip("/\\")
            p = os.path.join(xdir, safe)
            os.makedirs(os.path.dirname(p) or xdir, exist_ok=True)
            with open(p, "wb") as f:
                f.write(raw)
            if k in ("pe", "elf", "macho", "jar", "apk", "dex", "class", "script", "zip", "gzip", "tar", "pdf", "ole", "ooxml", "pyc"):
                analyze_file(p, outdir, args, depth + 1, rep_parent=rep)


def analyze_ole(data, path, rep):
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        rep.find(2, "tool", "OLE/macro bestand: pip install oletools voor macro extractie")
        for o, s in ascii_strings(data, 6):
            if re.search(r"(?i)autoopen|document_open|workbook_open|shell|createobject|powershell|http", s):
                rep.add("OLE strings", short(s, 160))
        return
    vp = VBA_Parser(path, data=data)
    if vp.detect_vba_macros():
        for (fn, sp, vfn, code) in vp.extract_macros():
            rep.add("VBA macro code", f"--- {vfn} ---")
            for line in code.splitlines()[:300]:
                rep.add("VBA macro code", line)
            deob_layers(code, rep, label="VBA")
        for kw_type, kw, desc in vp.analyze_macros():
            if kw_type in ("AutoExec", "Suspicious", "IOC"):
                rep.find(1 if kw_type != "Suspicious" else 2, "macro", f"{kw_type}: {kw} - {desc}")
    vp.close()


def analyze_pdf(data, path, rep):
    for kw in (b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch", b"/EmbeddedFile", b"/URI", b"/SubmitForm", b"/RichMedia", b"/XFA", b"/Encrypt"):
        c = data.count(kw)
        if c:
            rep.add("PDF", f"{kw.decode()} x{c}")
            if kw in (b"/JavaScript", b"/JS", b"/Launch", b"/EmbeddedFile", b"/OpenAction"):
                rep.find(2, "pdf", f"PDF bevat {kw.decode()} ({c}x)")
    n = 0
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.S):
        raw = m.group(1)
        try:
            dec = zlib.decompress(raw)
        except Exception:
            continue
        n += 1
        if re.search(rb"(?i)eval|unescape|String\.fromCharCode|app\.|this\.exportDataObject|util\.printf", dec):
            rep.add("PDF", f"JS-achtige stream @0x{m.start():x}: {short(dec[:300].decode('latin-1'), 300)}")
            rep.find(1, "pdf", f"Verdachte JavaScript in stream @0x{m.start():x}")
            deob_layers(dec.decode("latin-1"), rep, label="PDF JS")
    rep.add("PDF", f"{n} Flate streams gedecomprimeerd")


def analyze_pyc_file(data, path, rep):
    strs = marshal_strings(data[16:])
    rep.add("Python bytecode", " | ".join(repr(short(s, 60)) for s in strs[:150]))
    for s in strs:
        for cname, prio, val in classify_string(s):
            if prio <= 2:
                rep.find(prio, cname, short(val, 120))
    _decompile_pyc(path, rep)


# ---- Ghidra headless ---------------------------------------------------------------
GHIDRA_SCRIPT = r'''
// revkit: decompileer functies die interessante strings refereren (of alles)
//@category revkit
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import java.io.*;
import java.util.*;
import java.util.regex.*;

public class RevkitDecompile extends GhidraScript {
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String out = a[0];
        boolean all = a.length > 1 && a[1].equals("all");
        Pattern p = Pattern.compile("(?i)pass|wachtw|licen|serial|key|token|secret|wrong|incorrect|invalid|denied|granted|correct|login|auth|admin|flag|verify|enter|access");
        Set<Function> todo = new LinkedHashSet<>();
        FunctionManager fm = currentProgram.getFunctionManager();
        if (all) { for (Function f : fm.getFunctions(true)) if (!f.isThunk() && !f.isExternal()) todo.add(f); }
        else {
            for (Data d : currentProgram.getListing().getDefinedData(true)) {
                if (!(d.getValue() instanceof String)) continue;
                if (!p.matcher((String) d.getValue()).find()) continue;
                for (Reference r : getReferencesTo(d.getAddress())) {
                    Function f = fm.getFunctionContaining(r.getFromAddress());
                    if (f != null) todo.add(f);
                }
            }
            Function m = getGlobalFunctions("main").isEmpty() ? null : getGlobalFunctions("main").get(0);
            if (m != null) todo.add(m);
        }
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        PrintWriter w = new PrintWriter(new FileWriter(out));
        for (Function f : todo) {
            DecompileResults r = di.decompileFunction(f, 60, monitor);
            if (r != null && r.decompileCompleted()) {
                w.println("// ===== " + f.getName() + " @ " + f.getEntryPoint() + " =====");
                w.println(r.getDecompiledFunction().getC());
            }
        }
        w.close();
        println("revkit: " + todo.size() + " functies gedecompileerd -> " + out);
    }
}
'''


def run_ghidra(path, rep, outdir):
    import glob
    gh = os.environ.get("GHIDRA_HOME")
    cands = [shutil.which("analyzeHeadless"), os.path.join(gh, "support", "analyzeHeadless") if gh else None,
             "/usr/share/ghidra/support/analyzeHeadless"] + sorted(glob.glob("/opt/ghidra*/support/analyzeHeadless")) + \
            sorted(glob.glob(os.path.expanduser("~/ghidra*/support/analyzeHeadless")))
    hl = next((c for c in cands if c and os.path.exists(c)), None)
    if not hl or not os.path.exists(hl):
        rep.find(2, "tool", "--ghidra: Ghidra niet gevonden. Kali: `sudo apt install ghidra` (of zet GHIDRA_HOME naar je Ghidra-map)")
        return
    sd = tempfile.mkdtemp(prefix="revkit_gs_")
    with open(os.path.join(sd, "RevkitDecompile.java"), "w") as f:
        f.write(GHIDRA_SCRIPT)
    proj = tempfile.mkdtemp(prefix="revkit_gp_")
    out = os.path.join(outdir, "ghidra_decompiled.c")
    cmd = [hl, proj, "revkit", "-import", path, "-scriptPath", sd, "-postScript", "RevkitDecompile.java", out, "-deleteProject"]
    print(f"{C['d']}[*] Ghidra headless draait (kan minuten duren)...{C['x']}")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    if os.path.exists(out):
        rep.find(1, "decompile", f"Ghidra decompilatie van relevante functies -> {out}")
    else:
        rep.find(2, "tool", f"Ghidra faalde: {r.stdout[-400:]} {r.stderr[-400:]}")


# --------------------------------------------------------------------------- generieke string pass
def generic_strings(data, rep, args, skip_noise=True):
    n = 0
    hits = collections.defaultdict(list)
    for off, s in list(ascii_strings(data, 5)) + list(utf16_strings(data, 5)):
        n += 1
        if skip_noise and NOISE.search(s):
            continue
        for cname, prio, val in classify_string(s):
            hits[cname].append((off, s, val, prio))
    rep.meta["strings_total"] = n
    for cname, lst in sorted(hits.items(), key=lambda x: min(i[3] for i in x[1])):
        uniq = []
        seen = set()
        for off, s, val, prio in lst:
            if val in seen:
                continue
            seen.add(val)
            uniq.append((off, s, val, prio))
        for off, s, val, prio in uniq[:40]:
            rep.add("Strings (geclassificeerd)", f"[{cname:12}] 0x{off:08x}  {short(s, 150)}")
        if uniq and uniq[0][3] == 1 and cname not in ("auth-msg",):
            for off, s, val, prio in uniq[:5]:
                rep.find(1, cname, short(val, 140), f"offset 0x{off:x}")
        if cname == "auth-msg":
            rep.find(3, "auth", f"{len(uniq)} auth-gerelateerde string(s), bv: " + "; ".join(repr(short(u[1], 50)) for u in uniq[:4]))
    if args.all_strings:
        with open(os.path.join(rep.outdir, "strings.txt"), "w") as f:
            for off, s in ascii_strings(data, 4):
                f.write(f"0x{off:08x} A {s}\n")
            for off, s in utf16_strings(data, 4):
                f.write(f"0x{off:08x} W {s}\n")


# --------------------------------------------------------------------------- driver
def analyze_file(path, outdir, args, depth=0, rep_parent=None):
    with open(path, "rb") as f:
        data = f.read()
    rep = Report(path)
    sub = os.path.join(outdir, re.sub(r"[^\w.-]", "_", os.path.basename(path))) if depth else outdir
    os.makedirs(sub, exist_ok=True)
    rep.outdir = sub
    kind = detect(data, path)
    rep.meta.update({"file": path, "size": len(data), "type": kind, "md5": hashlib.md5(data).hexdigest(),
                     "sha256": hashlib.sha256(data).hexdigest(), "entropy": round(entropy(data), 3)})
    print(f"{C['B']}{'  ' * depth}[+] {os.path.basename(path)}  ->  {kind}  ({len(data)} bytes){C['x']}")
    try:
        if kind == "pe":
            analyze_pe(data, path, rep, args, sub, depth)
        elif kind in ("elf", "macho"):
            analyze_elf_macho(data, path, rep, args, sub, depth, kind)
        elif kind in ("jar", "apk"):
            analyze_jar_apk(data, path, rep, sub, kind)
        elif kind == "class":
            analyze_java_class(data, os.path.basename(path), rep)
        elif kind == "dex":
            for s in dex_strings(data):
                for cname, prio, val in classify_string(s):
                    if prio <= 2:
                        rep.add("DEX strings (geclassificeerd)", f"[{cname}] {short(s, 120)}")
        elif kind in ("zip", "tar", "gzip", "ooxml"):
            analyze_archive(data, path, rep, sub, args, depth, kind)
        elif kind == "ole":
            analyze_ole(data, path, rep)
        elif kind == "pdf":
            analyze_pdf(data, path, rep)
        elif kind == "pyc":
            analyze_pyc_file(data, path, rep)
        elif kind == "script":
            analyze_script(data, path, rep)
        else:
            rep.find(3, "blob", f"Onbekend formaat (entropie {entropy(data):.2f}); "
                     + ("waarschijnlijk versleuteld/gecomprimeerd" if entropy(data) > 7.5 else "probeer XOR/base64 decoders"))
            x = _xor_brute(data[:4096]) if entropy(data) < 7.5 else None
            if x:
                kd = f"0x{x[0]:02x}" if isinstance(x[0], int) else x[0].hex()
                rep.find(1, "xor", f"Blob is XOR-encoded met key {kd}: {short(x[1], 140)}")
                for cname, prio, val in classify_string(x[1]):
                    rep.find(prio, cname, f"na XOR-decode: {short(val, 120)}")
    except Exception as e:
        import traceback
        rep.find(2, "error", f"Analyse-fout in {kind}-module: {e}", traceback.format_exc()[-600:])
    if kind not in ("script",):
        generic_strings(data, rep, args, skip_noise=True)
    if kind not in ("zip", "jar", "apk", "ooxml", "tar", "gzip"):
        scan_crypto(data, rep)
    if kind not in ("zip", "jar", "apk", "ooxml"):
        carve(data, rep, sub, args.carve)
    emit(rep, sub, depth)
    if rep_parent is not None:
        for f in rep.findings:
            rep_parent.find(f[0], f[1], f"[{os.path.basename(path)}] {f[2]}", f[3])
    return rep


def emit(rep, outdir, depth):
    ind = "  " * depth
    hdr(f"{ind}Basisinfo: {os.path.basename(rep.path)}")
    for k, v in rep.meta.items():
        print(f"{ind}  {k:22}: {v}")
    order = ["Auth / check-logica (gereconstrueerd)", "Kandidaat secrets", ".NET methode-strings", "Stack strings",
             "Interessante imports", "Interessante functienamen", "Strings met code-referentie"]
    keys = order + [k for k in rep.sections if k not in order]
    for k in keys:
        if k not in rep.sections:
            continue
        lines = rep.sections[k]
        hdr(f"{ind}{k}")
        lim = 60
        for l in lines[:lim]:
            print(f"{ind}  {l}")
        if len(lines) > lim:
            print(f"{ind}  {C['d']}... +{len(lines) - lim} (zie report.md){C['x']}")
    hdr(f"{ind}TOP FINDINGS")
    for prio, cat, text, ev in sorted(rep.findings, key=lambda f: f[0]):
        print(f"{ind}  {PRIO_COL[prio]}[{PRIO_TXT[prio]}]{C['x']} {C['B']}{cat:11}{C['x']} {text}")
        if ev and prio <= 2:
            print(f"{ind}               {C['d']}{short(ev, 200)}{C['x']}")
    # bestanden
    with open(os.path.join(outdir, "report.md"), "w") as f:
        f.write(f"# revkit rapport: {os.path.basename(rep.path)}\n\n## Top findings\n\n")
        for prio, cat, text, ev in sorted(rep.findings, key=lambda x: x[0]):
            f.write(f"- **{PRIO_TXT[prio].strip()}** `{cat}` {text}" + (f"  \n  _{ev}_" if ev else "") + "\n")
        f.write("\n## Basisinfo\n\n")
        for k, v in rep.meta.items():
            f.write(f"- {k}: `{v}`\n")
        for k in keys:
            if k in rep.sections:
                f.write(f"\n## {k}\n\n```\n" + "\n".join(rep.sections[k]) + "\n```\n")
    with open(os.path.join(outdir, "report.json"), "w") as f:
        json.dump({"meta": rep.meta, "findings": [dict(prio=p, cat=c, text=t, evidence=e) for p, c, t, e in rep.findings],
                   "sections": rep.sections}, f, indent=2, default=str)
    print(f"\n{ind}{C['g']}[✓] Rapport: {os.path.join(outdir, 'report.md')}  (+ report.json){C['x']}")


def main():
    ap = argparse.ArgumentParser(prog="revkit", description="revkit - universele static reverse-engineering triage")
    ap.add_argument("file", help="te analyseren bestand (wordt nooit uitgevoerd)")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("-o", "--outdir", help="output map (default: <file>_revkit)")
    ap.add_argument("--ghidra", action="store_true", help="decompileer relevante functies met Ghidra headless (GHIDRA_HOME)")
    ap.add_argument("--all-strings", action="store_true", help="schrijf alle strings naar strings.txt")
    ap.add_argument("--carve", action="store_true", help="extraheer embedded bestanden")
    ap.add_argument("--max-depth", type=int, default=3, help="recursiediepte voor archives/embedded (default 3)")
    args = ap.parse_args()
    if capstone is None or pefile is None:
        print(f"{C['y']}[!] installeer minimaal: pip install capstone pefile lief dnfile oletools{C['x']}")
    if not os.path.isfile(args.file):
        ap.error(f"bestand niet gevonden: {args.file}")
    out = args.outdir or (args.file.rstrip("/\\") + "_revkit")
    os.makedirs(out, exist_ok=True)
    analyze_file(args.file, out, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
