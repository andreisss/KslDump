# KslDump - BMVD (Bring the Microsoft Vulnerable Driver) 

> **Why bring your own knife when Defender already left one in the kitchen?**

KslDump extracts credentials from PPL-protected LSASS using only Microsoft-signed components. No exploit is deployed. No driver is loaded. The entire attack chain ships pre-installed with Windows Defender. Microsoft patched the running version (wd\KslD.sys) by nulling out MmCopyMemory, but left the old vulnerable version (drivers\KslD.sys) sitting on disk. The attacker doesn't bring anything — they just point the service back to what Microsoft forgot to clean up.

  ┌────────────────┬───────────────────────────────────────────┬─────────────────────────────────────────────────────────────────────────────────────────────┐
  │                │                   BYOVD                   │                        BMVD (Bring the Microsoft Vulnerable Driver)                         │
  ├────────────────┼───────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Driver source  │ Attacker brings a 3rd-party signed driver │ Already on disk, shipped by Microsoft                                                       │
  ├────────────────┼───────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Driver signing │ Needs a legitimately signed driver        │ Microsoft-signed (part of Defender)                                                         │
  ├────────────────┼───────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Driver loading │ Must load a new driver (detectable)       │ Just changes ImagePath to an existing .sys                                                  │
  ├────────────────┼───────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Detection      │ EDR can flag new driver loads             │ No new driver on disk, no new signing cert — just a registry value change + service restart │
  ├────────────────┼───────────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Artifacts      │ Foreign .sys file on disk                 │ Zero new files — both drivers are stock Windows                                             │
  └────────────────┴───────────────────────────────────────────┴─────────────────────────────────────────────────────────────────────────────────────────────┘

---

## The Vulnerability

**KslD.sys** is a kernel driver shipped with Microsoft Defender. It is **Microsoft-signed**, loaded as a trusted kernel module, and exposes a device object `\\.\KslD` accessible from usermode.

The driver accepts IOCTL `0x222044` with multiple sub-commands that provide **unrestricted kernel and physical memory access** to any process that can open the device handle.

### Vulnerable Sub-Commands

| SubCmd | Capability | Impact |
|--------|-----------|--------|
| **2** | Returns CR3, IDTR, and other CPU control registers to usermode | Instant KASLR defeat |
| **12** | Calls `MmCopyMemory()` with attacker-controlled address and size | Arbitrary kernel/physical memory read |

### The "Access Control"

The only gate to the device handle is a **process name string** stored in a registry key (`AllowedProcessName`) under the driver's service key. This value is:

- Editable by any local administrator
- Not protected by Defender's tamper protection
- Not validated against code signing, integrity, or any binary property
- A plain string comparison — rename your binary and you're in

---

## The Incomplete Patch

Microsoft identified the issue and partially fixed SubCmd 12 in a newer build. But they left the vulnerable binary on disk, sitting right next to the patch.

| | `drivers\wd\KslD.sys` (82 KB) | `drivers\KslD.sys` (333 KB) |
|---|---|---|
| **Version** | 1.1.25111 (newer) | 1.1.25081 (older) |
| **Loaded by default** | Yes (`ImagePath` points here) | No (orphaned on disk) |
| **Intel TDT engine** | Removed | Included (~250 KB extra code) |
| **MmCopyMemory** | Resolved then **set to NULL** | Resolved and **stored** |
| **SubCmd 12** | Returns `STATUS_NOT_SUPPORTED` | **Works — arbitrary read** |
| **Signed by** | Microsoft | Microsoft |

The difference is one line in `CCommand::Initialize`:

```c
// 82 KB version (patched) — deliberately clears the pointer:
v3 = MmGetSystemRoutineAddress(L"MmCopyMemory");
if (v3 >= 0) {
    *(a1 + 24) = 0;        // ← NULLs it — SubCmd 12 is dead
}

// 333 KB version (vulnerable) — stores the pointer:
ptr = MmGetSystemRoutineAddress(L"MmCopyMemory");
if (ptr) {
    *(this + 0x18) = ptr;   // ← Keeps it — SubCmd 12 works
}
```

Defender platform updates appear to drop the patched 82 KB version into `drivers\wd\` and point `ImagePath` at it, while the older 333 KB version remains in `drivers\`. On tested systems, the old binary was never removed. The exploit simply switches `ImagePath` back to the vulnerable version and restarts the service. Both binaries are Microsoft-signed and trusted by the OS.

---

## Why The Old Driver Is Still On Disk

The 333 KB KslD.sys is part of the Windows Component Store (https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/manage-the-component-store?view=windows-11). On the tested system, drivers\KslD.sys and its WinSxS copy share the same NTFS file ID, confirmed via fsutil hardlink list. This is https://learn.microsoft.com/en-us/archive/blogs/askcore/what-is-the-winsxs-directory-in-windows-2008-and-windows-vista-and-why-is-it-so-large — system files in System32 are projected from WinSxS via hardlinks.

The 82 KB patched version is deployed separately by https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-updates (KB4052623) into drivers\wd\, hardlinked to ProgramData\Microsoft\Windows Defender\Platform\. The component store's https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/clean-up-the-winsxs-folder?view=windows-11 (StartComponentCleanup) only removes components when a newer CBS version supersedes them, after a 30-day grace period. On the tested system, the 333 KB binary belongs to CBS component version 10.0.26100.7309 — the latest version. No newer CBS version exists, so there is nothing to supersede it and nothing for cleanup to remove.

The fix was shipped through the Defender platform update channel, not through a CBS update. The Windows servicing stack still considers the vulnerable 333 KB version current and valid. If Microsoft eventually ships a CBS update that supersedes it, the old binary would be cleaned up after 30 days. Until then, it stays.

---

## The Blocklist Paradox

Microsoft maintains a [Vulnerable Driver Blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) (`DriverSiPolicy.p7b`) specifically to prevent BYOVD attacks. This blocklist is enforced via HVCI and blocks known-vulnerable signed drivers from loading.

From Microsoft's own documentation:

> *"The vulnerable driver blocklist is designed to help harden systems against **non-Microsoft-developed drivers** across the Windows ecosystem"*

**Microsoft's own drivers are excluded from the blocklist by design.**

---

## Why This Works

The root cause is simple: **MmCopyMemory does not respect PPL**.

PPL (Protected Process Light) was designed to prevent credential theft by blocking `OpenProcess` and `ReadProcessMemory` calls against LSASS. But PPL only protects the **usermode API path**. It has no authority over kernel-mode physical memory reads.

KslD.sys gives usermode code a direct path to `MmCopyMemory()` — Microsoft's own kernel API for copying memory by physical or virtual address. The driver performs:

- **No address range validation** — any physical address is accepted
- **No size limit enforcement** — read as much as you want
- **No caller verification** beyond a registry string check that an admin can edit

The result: a Microsoft-signed driver provides a complete PPL bypass out of the box.

---

## The Read Primitive

The core of the vulnerability is **SubCmd 12** — an unrestricted `MmCopyMemory()` wrapper:

```
IOCTL:    0x222044
Input:    struct {
            DWORD  SubCmd;       // 12
            DWORD  Reserved;     // 0
            QWORD  Address;      // Target VA or PA
            QWORD  Size;         // Bytes to read
            DWORD  Flags;        // 1 = Physical, 2 = Virtual
            DWORD  Padding;
          }
Output:   Raw memory contents (up to Size bytes)
```

**Physical read** (Flags = 1) is the critical primitive. Physical memory access is not subject to process protection levels, EPROCESS flags, or any usermode API restrictions, this is what bypasses PPL.

**Virtual read** (Flags = 2) reads kernel virtual addresses directly, useful for walking kernel structures (EPROCESS, ntoskrnl exports) without manual page table translation.

---
---

## Attack Chain

```
┌──────────────────────────────────────────────────────────────────┐
│                        KslDump Attack Flow                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Registry Edit         ImagePath ← vulnerable 333KB KslD.sys *│
│          │                AllowedProcessName ← our process       │
│          │                sc stop/start KslD                     │
│          ▼                                                       │
│  2. KASLR Bypass          SubCmd 2 → CR3 + IDTR                  │
│          │                IDT → lowest ISR → ntoskrnl base       │
│          ▼                                                       │
│  3. Kernel Walk           PsInitialSystemProcess → SYSTEM EPROC  │
│          │                ActiveProcessLinks → find lsass.exe    │
│          │                Read lsass DTB from EPROCESS+0x28      │
│          ▼                      (all via SubCmd 12, flags=2)     │
│                                                                  │
│  4. Physical Read         Page table walk using lsass DTB        │
│          │                MmCopyMemory() reads lsass pages       │
│          │                      *** BYPASSES PPL ***             │
│          ▼                      (SubCmd 12, flags=1)             │
│                                                                  │
│  5. Key Extraction        Find lsasrv.dll via PEB → LDR         │
│          │                Scan .text for LSA key signatures      │
│          │                Follow BCRYPT chain → AES + 3DES + IV  │
│          ▼                                                       │
│  6. Credential Dump       Walk LogonSessionList                  │
│                           Decrypt MSV1_0 credentials             │
│                           → NT hashes                            │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```
---

## What Gets Bypassed

| Protection | Bypassed | Why |
|-----------|----------|-----|
| **KASLR** | Yes | SubCmd 2 hands CR3 + IDTR directly to usermode — no guessing needed |
| **PPL (RunAsPPL = 2)** | Yes | Physical reads via MmCopyMemory are not subject to process protection levels |
| **Windows Defender Real-Time** | Yes | Defender cannot detect IOCTL calls to its own driver — the attack surface IS Defender |
| **Defender Behavior Monitor** | Yes | No behavioral detection triggered — the IOCTLs are to a trusted Microsoft driver |
| **Defender Tamper Protection** | Yes | Tamper protection does not cover the KslD service registry key |
| **Vulnerable Driver Blocklist** | N/A | Microsoft-signed drivers are excluded from the blocklist by design |

### Credential Guard

During testing, Credential Guard was fully configured:

- `LsaCfgFlags = 1` (enabled via registry)
- `SecurityServicesConfigured = {1}` (CG configured in WMI)
- `VirtualizationBasedSecurityStatus = 2` (VBS reported as running)
- `LsaIso.exe` actively running

Despite all of this, extracted credentials showed `isIso=0` — **credentials were not isolated**. WMI reported `SecurityServicesRunning = {0}` and `VirtualMachineIsolation = False`, indicating CG was in a degraded state where LsaIso.exe runs but does not actually protect credential material.

---

### Requirements

- Local administrator privileges
- Python 3.x with `cryptography` package (`pip install cryptography`)
- The vulnerable 333 KB KslD.sys must exist on disk (default: `C:\Windows\System32\drivers\KslD.sys`)

---

## The Irony — A Summary

The attack requires no third-party drivers, no unsigned code, no exploits. Everything is Microsoft-signed, Microsoft-shipped, and already on the system. The vulnerable driver sits on disk next to its own patch, excluded from the blocklist meant to prevent exactly this class of attack.

---

## Responsible Disclosure

This vulnerability was reported to Microsoft Security Response Center (MSRC). They closed it as **"Not a Vulnerability"** with the following rationale:

> *"The described attack depends on pre-existing administrative privileges. No evidence was provided showing how those privileges were obtained. Reports that assume administrative or root access without demonstrating a vulnerability that grants those privileges are considered lower impact, as an attacker with such access could already perform more severe actions."*

No CVE was assigned. No fix was issued.

---

## Disclaimer

This tool is provided for **authorized security testing and research purposes only**. Use it only on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The author assumes no liability for misuse.

---
