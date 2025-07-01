# 🛡️ HunterSuite - GUI-Based Penetration Testing Toolkit

**HunterSuite** is a modern, graphical penetration testing toolkit designed for cybersecurity professionals, students, and enthusiasts. It combines essential offensive security tools into a sleek, PyQt5-powered user interface — making network scanning and attack simulations more accessible, visual, and effective.

---

## ✨ Key Features (with Explanation)

### 🔍 1. Port Scanner
- **Purpose:** To identify which ports are open on a target IP/domain.
- **Use Cases:** Find exposed services like FTP, SSH, HTTP, etc.
- **Options:**
  - Common Ports (21, 22, 23, 80, 443)
  - Top 100 ports
  - Custom ports (user-defined)

### 🔐 2. Brute Force Login
- **Purpose:** Simulates password attacks on a web login form.
- **Functionality:** Sends POST requests with multiple password guesses.
- **Input Fields:**
  - Login URL
  - Username
  - Passwords (manual input or loaded from a file)

### 🌐 3. Web Page Link Scanner
- **Purpose:** Extracts and lists all hyperlinks from a webpage.
- **Use Cases:** Reconnaissance, sitemap creation, target discovery.

### 🔑 4. Hash Cracker (MD5)
- **Purpose:** Attempts to reverse-engineer a given MD5 hash using a wordlist.
- **Real-world use:** Password recovery, security analysis.
- **Hash Type Supported:** MD5 (32-character hashes)

### 💻 5. Modern GUI
- **Built With:** PyQt5
- **Features:**
  - Tabs for each tool
  - Progress bars
  - Live scan logs
  - Tooltips for guidance
  - Dark theme for ease on eyes

---

## 🛠️ System Requirements

- **Python Version:** 3.7 or higher
- **Libraries Required:**
  - `PyQt5`
  - `requests`
  - `beautifulsoup4`

### 📦 Install Dependencies
```bash
pip install -r requirements.txt
