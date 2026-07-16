# 🟩 HTB (Hack The Box)

This folder collects all the work done on the [Hack The Box](https://www.hackthebox.com/) platform: machine writeups, CTF challenge notes, and progress through the Academy learning paths.

Each writeup documents the full process — reconnaissance, enumeration, exploitation, and flag retrieval — along with the reasoning behind each decision and the defensive lessons that follow from it. The goal is not only to record *what* was done, but *why* each step was chosen, so that each writeup stands on its own as a small technical report rather than a list of commands.

All writeups are produced against intentionally vulnerable, HTB-provided lab targets, in accordance with the platform's terms of use.

---

## 📁 Structure

```
HTB (Hack The Box)/
├── README.md                  # This file
├── CTF/
│   └── README.md              # Notes and writeups for standalone CTF challenges
└── Starting-Point/Tier-0/
    ├── 1 - Meow/
    ├── 2 - Fawn/
    ├── 3 - Dancing/
    ├── 4 - Redeemer/
    └── README.md              # Tier-0 index
```

### `Starting-Point/`
Writeups for the HTB Starting Point machines. The Starting Point is split into tiers on the platform, and each tier has its own folder — currently Tier-0, covering the eight machines from Meow through Synced.

Inside a tier, each machine lives in its own folder, prefixed with a number. The number is used purely for ordering and matches the sequence in which HTB itself lists the machines, so the directory reads as the intended learning progression instead of being sorted alphabetically.

Every machine folder follows the same layout:

```
N - MachineName/
├── README.md      # The writeup
└── Images/        # Terminal screenshots referenced by the writeup
```

### `CTF/`
Writeups and notes for standalone HTB CTF challenges (web, crypto, reversing, etc.), which are not tied to a machine or tier.

---

## 📝 Writeup Format

Every machine writeup follows a consistent template:

| Section | Purpose |
|---|---|
| **Header** | Platform, machine, difficulty, OS, date |
| **Objective** | What the machine explores, based on the official machine description |
| **Technical Questions & Tasks** | The platform's guided task answers |
| **Step-by-Step Exploitation** | The attack narrative, with reasoning and screenshots |
| **Technical Summary** | The kill chain condensed into a few numbered steps |
| **Lessons Learned** | Defensive takeaways and operational notes |

Writeups are written in the first person plural (`we`), following the convention used in professional penetration testing reports.

---

## 📈 Current Progress

- [x] HTB Starting Point - Tier 0 (Only the free machines)
  <details>
  <summary><i>Click to expand machines</i></summary>

  - [x] HTB Starting Point — Meow
  - [x] HTB Starting Point — Fawn
  - [x] HTB Starting Point — Dancing
  - [x] HTB Starting Point — Redeemer
  - [ ] HTB Starting Point (VIP+) — Explosion
  - [ ] HTB Starting Point (VIP+) — Preignition
  - [ ] HTB Starting Point (VIP+) — Mongod
  - [ ] HTB Starting Point (VIP+) — Synced

  </details>

- [ ] HTB Certified SOC Analyst Path
  <details>
  <summary><i>Click to expand modules</i></summary>

  - [x] Incident Handling Process
  - [ ] Security Monitoring & SIEM Fundamentals
  - [ ] Windows Event Logs & Finding Evil
  - [ ] Introduction To Threat Hunting & Hunting With Elastic
  - [ ] Understanding Log Sources & Investigating With Splunk
  - [ ] Windows Attacks & Defense
  - [ ] Intro To Network Traffic Analysis
  - [ ] Intermediate Network Traffic Analysis
  - [ ] Working With IDS/IPS
  - [ ] Introduction To Malware Analysis
  - [ ] JavaScript Deobfuscation
  - [ ] YARA & Sigma For SOC Analysts
  - [ ] Introduction To Digital Forensics
  - [ ] Detecting Windows Attacks With Splunk
  - [ ] Security Incident Reporting

  </details>
