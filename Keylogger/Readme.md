🔑 Python Keylogger (For Educational & Testing Use Only)
This is a simple Python-based keylogger built using the keyboard library. It captures and logs every key press with a timestamp and writes it to a local log file named keystrokes.log.

⚠️ Disclaimer: This tool is intended strictly for educational purposes, such as security research, penetration testing (in a legal and authorized environment), or cybersecurity portfolio development. Do not use this script on devices or systems without explicit permission. Unauthorized usage is unethical and illegal.

📌 Features
Logs all keypresses in real-time

Adds timestamps for each key event

Continues to run silently in the background until Esc is pressed

Saves logs in keystrokes.log in the script directory

🛠 Requirements
Python 3.x

keyboard module

You can install the required library using:

bash
Copy
Edit
pip install keyboard
🚀 How to Use
Clone the repository or download the script.

Run the Python file:

bash
Copy
Edit
python keylogger.py
The keylogger will start and continue logging until the Esc key is pressed.

Check the generated keystrokes.log file for the logs.

📁 Log Format
Each key press is logged with a timestamp. Example:

vbnet
Copy
Edit
2025-06-17 20:34:12 - Key pressed: a
2025-06-17 20:34:13 - Key pressed: shift
2025-06-17 20:34:14 - Key pressed: B
🔒 Ethical Usage Guidelines
Only run this tool on your own system or authorized test environments.

Use it to learn, experiment, or demonstrate basic security logging.

Violating user privacy or monitoring systems without permission is illegal and violates ethical standards in cybersecurity.

📚 Purpose
This project is part of a cybersecurity learning portfolio. It demonstrates basic event capturing techniques using Python and reinforces ethical programming practices in security research.

