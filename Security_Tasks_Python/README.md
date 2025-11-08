# 🧠 Cybersecurity Python Tools

A collection of beginner–friendly Python tools for cybersecurity learning and automation.
Each tool demonstrates a different core concept, from encryption to network analysis.

📂 Included Tools
1. Caesar Cipher - Classic text encryption using shift-based substitution.
2. Image Encryption (Pixel Manipulation) - Encrypts/decrypts images by modifying pixel data using a key.
3. Password Strength Checker - Evaluates password complexity and gives feedback.
4. Simple Keylogger	- Logs keyboard input for educational purposes (ethical use only).
5. Network Packet Analyzer - Captures and displays packet-level network traffic using Scapy.

🔧 Prerequisites

Make sure you have Python 3 installed.

Install dependencies with:

pip install -r requirements.txt

🧩 Usage

Each tool can be run individually:

python Caesar_Cipher/caesar_cipher.py

python Image_Encryption/image_encryption.py

python Password_Checker/password_strength_checker.py

python Keylogger/simple_keylogger.py

python Packet_Analyzer/network_packet_analyzer.py

⚙️ Features Overview

🧾 1. Caesar Cipher

Encrypts and decrypts text using a shift value.

Demonstrates basic cryptography and modular arithmetic.

🖼️ 2. Image Encryption

Uses Pillow for pixel manipulation.

Swaps pixel values using a numeric key.

Supports both encryption and decryption.

🔐 3. Password Strength Checker

Evaluates password security using regex.

Provides detailed feedback (length, cases, numbers, symbols).

⌨️ 4. Simple Keylogger (Ethical Use Only)

Logs keystrokes using pynput.

Stores results in a keylog.txt file.

Stops when Esc key is pressed.

🌐 5. Network Packet Analyzer

Uses Scapy to sniff live network traffic.

Displays source/destination IP, protocol, ports, and payload.

For educational network security experiments only.

🧰 Technologies Used

Python 3

Pillow (Image processing)

pynput (Keyboard monitoring)

scapy (Network packet analysis)

Regular Expressions

⚠️ Ethical Disclaimer

These scripts are for educational and ethical use only.
Do not use them to monitor, log, or intercept data without explicit permission.

📚 Learning Outcomes

Understanding of basic cryptography, Fundamentals of image data manipulation,

Use of regex for security validation, Basics of keyboard and network event monitoring.
