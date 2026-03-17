# KslDump - BMVD (Bring the Microsoft Vulnerable Driver) 


  [![GitHub stars](https://img.shields.io/github/stars/andreisss/KslDump?style=social)](https://github.com/andreisss/KslDump/stargazers)
  [![GitHub forks](https://img.shields.io/github/forks/andreisss/KslDump?style=social)](https://github.com/andreisss/KslDump/network)
  [![GitHub downloads](https://img.shields.io/github/downloads/andreisss/KslDump/total)](https://github.com/andreisss/KslDump/releases)
  [![Sponsor](https://img.shields.io/badge/Sponsor-❤-red)](https://github.com/sponsors/andreisss)
  [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

> **Why bring your own knife when Defender already left one in the kitchen?**

KslDump extracts credentials from PPL-protected LSASS using only Microsoft-signed components. No exploit is deployed. No driver is loaded. The entire attack chain ships pre-installed with Windows Defender. Microsoft patched the running version (wd\KslD.sys) by nulling out MmCopyMemory, but left the old vulnerable version (drivers\KslD.sys) sitting on disk. The attacker doesn't bring anything — they just point the service back to what Microsoft forgot to clean up.

<img width="1517" height="258" alt="image" src="https://github.com/user-attachments/assets/89ca7a1f-e3c1-4d7a-9812-dc7f7ddc3d4a" />



https://github.com/user-attachments/assets/78dfce25-56b3-4eb8-9de2-7c183601e597


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

## Why The Old Driver Is Still On Disk - personal theory

Microsoft’s public documentation shows that KB4052623 delivers Defender platform updates, including a historical move of Defender drivers to System32\drivers\wd, while Windows servicing keeps WinSxS-backed component-store files via NTFS hard links and only removes superseded component versions during cleanup. On the tested system, this explains why the newer 82 KB KslD.sys could arrive through the Defender platform-update path while the older 333 KB System32\drivers\KslD.sys remained present as the current CBS-backed component-store copy until superseded by a newer CBS version.

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
