# HTB Starting Point — Meow

**Platform:** Hack The Box — Starting Point (Tier 0)  
**Machine:** Meow  
**Difficulty:** Very Easy  
**Date:** 2026-07-10  

---

## Objective
Gaining unauthorized root access to the target machine and capturing the proof-of-compromise flag (`flag.txt`).

---

## Technical Questions & Tasks

### Task 1 — What does VM stand for?
**Answer:** `Virtual Machine`

### Task 2 — Tool used to interact with the OS via command line
**Answer:** `terminal`

### Task 3 — Service used to form the VPN connection into HTB labs
**Answer:** `OpenVPN`

### Task 4 — Tool used to test connectivity with an ICMP echo request
**Answer:** `ping`

### Task 5 — Most common tool for finding open ports on a target
**Answer:** `nmap`

### Task 6 — Service identified on port 23/tcp
**Answer:** `telnet`

### Task 7 — Username able to log in over telnet with a blank password
**Answer:** `root`

---

## Walkthrough & Exploitation Logic

### 1. Reconnaissance & Enumeration
We start by running a basic port scan to identify open ports and services running on the target.

```bash
nmap 10.129.138.45
```

![Nmap Scan Result](Images/Nmap%20Scan.png)

**Relevant Output:**
```text
Nmap scan report for 10.129.138.45
Host is up (0.071s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE
23/tcp open  telnet
```

**Logic:** Port `23/tcp` is open, indicating an active Telnet service. Telnet is a legacy protocol that transmits data in cleartext and is often plagued by weak credential policies in training environments.

### 2. Exploitation (Initial Access)
Since Telnet is exposed, we attempt a direct connection using the default administrative username (`root`) with a blank password.

```bash
telnet 10.129.138.45
```

![Telnet Connection Success](Images/Telnet%20Login.png)

**Result:** The target accepts the login without requesting a password, granting us an interactive shell with highest privileges (`root`).

### 3. Post-Exploitation & Flag Capture
Now inside the machine, we list the directory contents and read the flag file.

```bash
ls
cat flag.txt
```

![Flag Retrieval](Images/Flag%20Cat.png)

**Flag:** ✅ `Root flag owned`

---

## Technical Summary
1. **Recon:** Checked open doors with `nmap` and discovered Telnet (port 23).
2. **Exploit:** Connected via `telnet` using default `root` access and zero password credentials.
3. **Exfiltrate:** Explored the filesystem to capture `flag.txt`.

---

## Lessons Learned
- **Disable Telnet:** It transmits traffic in plaintext. Secure protocols like SSH should be used instead.
- **Enforce Password Policies:** The root account must never remain accessible with blank or default passwords.
- **Workflow Efficiency:** A simple approach (**Scan → Connect → Collect**) is sufficient for misconfigured entry-level machines.
