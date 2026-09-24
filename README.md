OFDT — Discord Username Checker

📌 Description

OFDT is a Python tool designed to generate different username combinations and check their availability on Discord.

The project provides multiple generation modes, proxy support, local SQLite history, and Discord webhook notifications.

The main program is contained in a single Python file: "OFDT src.py".

«⚠️ Use this project responsibly and in accordance with Discord's Terms of Service. Automated requests may be rate-limited or blocked.»

---

✨ Features

- Automatic username generation
- Multiple username generation modes
- Discord availability checking
- HTTP/HTTPS/SOCKS proxy support
- Rate-limit and error handling
- Local SQLite history
- Saves available usernames to "available.txt"
- Discord webhook notifications
- Multiple HTTP backends:
  - "curl_cffi"
  - "tls_client"
  - "requests" fallback

The program automatically falls back to "requests" when the optional HTTP backends are unavailable.

---

📦 Installation

1. Install Python

Python 3.10+ is recommended.

Check your Python version:

python --version

or:

python3 --version

---

2. Clone the repository

git clone https://github.com/c9splltop/4c-checker-discord-cracked.git
cd YOUR-REPOSITORY

---

3. Install the dependencies

Install the required packages:

python -m pip install requests curl_cffi tls-client

Alternatively, create a "requirements.txt" file containing:

requests
curl_cffi
tls-client

Then install everything with:

python -m pip install -r requirements.txt

---

📱 Termux Installation

If you are using Android with Termux:

pkg update
pkg upgrade
pkg install python git

Clone the repository:

git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
cd YOUR-REPOSITORY

Install the dependencies:

python -m pip install requests

You can also try installing the optional HTTP backends:

python -m pip install curl_cffi tls-client

If those packages cannot be installed on your Termux environment, "requests" can be used as the fallback HTTP backend.

---

▶️ Usage

Run the program with:

python "OFDT src.py"

If you renamed the file:

python OFDT.py

---

📁 Files

The program uses several local files:

Ogsniper-rapid-settings.json
proxies.txt
available.txt
Ogsniper-history.sqlite3
words.txt

"proxies.txt"

Proxies can be added one per line:

http://IP:PORT

or:

IP:PORT

The program handles different proxy formats automatically.

---

🔔 Discord Webhook

The program can send available usernames to a Discord webhook.

Never publish your webhook URL publicly on GitHub.

If you accidentally expose a webhook, regenerate it immediately.

---

⚙️ Generation Modes

The project includes multiple generation modes, including:

- Semi 3 Characters
- Semi 3 Numbers
- Semi 4 Numbers
- 2 Characters
- 3 Characters
- 4 Characters
- 5 Characters
- 3/4/5 Letters
- 3/4/5 Numbers
- Short Words
- Rare Words
- Obscure Words
- Word Combinations
- Dictionary
- Dictionary Combinations
- Word + Number + Word combinations

---

🛠️ Dependencies

External packages

Package| Purpose
"requests"| HTTP fallback backend
"curl_cffi"| HTTP backend
"tls-client"| Alternative HTTP backend

Python standard library

The project also uses modules included with Python, such as:

base64
json
math
os
queue
random
re
sqlite3
string
threading
time
uuid
pathlib
urllib
concurrent.futures
dataclasses
typing

These modules do not need to be installed with "pip".

---

⚠️ Rate Limits

Discord may return HTTP responses such as "429", "401", or "403".

The program includes mechanisms for handling these responses and temporarily pausing problematic routes.

Using proxies does not guarantee that rate limits will be avoided.

---

🔐 Security

Do not upload sensitive information to GitHub, including:

- Discord webhook URLs
- Authentication tokens
- Private proxies
- API keys
- Personal credentials

Use ".gitignore" for local configuration files when necessary.

---

📜 License

Choose and specify your preferred license here.

Example:

MIT License

---

⭐ Credits

A Python project focused on username generation, HTTP requests, proxy management, and Discord availability checking.

If you find the project useful, consider giving the repository a ⭐.
