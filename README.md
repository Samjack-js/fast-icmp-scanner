# ⚡ Fast ICMP Network Scanner

A simple and fast ICMP-based network scanner written in Python using raw sockets.

## 🧠 Overview

This project scans a target subnet using ICMP packets to identify active hosts.

It works similarly to basic network discovery tools like `ping sweep` or `nmap -sn`.

---

## 🚀 Features

- Raw socket ICMP packet crafting
- Custom checksum implementation
- Multithreaded scanning
- Fast network sweep
- Active host detection

---

## 🛠️ Technologies Used

- Python
- Socket programming
- Threading
- IP networking

---

## ⚠️ Requirements

- Root/Admin privileges (required for raw sockets)

---

## 📌 Usage

```bash
python scanner.py
