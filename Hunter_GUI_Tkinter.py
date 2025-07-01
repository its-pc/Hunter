import sys
import socket
import requests
from bs4 import BeautifulSoup
import hashlib
import re
import time
import platform
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QLineEdit, QPushButton, QTextEdit, QProgressBar, QComboBox,
    QListWidget, QSplitter, QFrame, QMessageBox, QFileDialog, QGroupBox,
    QGridLayout, QSizePolicy, QSpacerItem, QStatusBar, QToolTip
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer
from PyQt5.QtGui import QFont, QPalette, QColor, QTextCursor, QIcon, QFontDatabase

# =====================
# Utility Functions
# =====================
def validate_ip(ip):
    pattern = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
    if pattern.match(ip):
        return all(0 <= int(octet) <= 255 for octet in ip.split('.'))
    return False

def validate_url(url):
    pattern = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return pattern.match(url) is not None

def validate_hash(hash_str):
    return len(hash_str) == 32 and all(c in "0123456789abcdef" for c in hash_str.lower())

# =====================
# Worker Threads
# =====================
class PortScannerThread(QThread):
    update_signal = pyqtSignal(str, int, bool)
    finished_signal = pyqtSignal(list)
    progress_signal = pyqtSignal(int)
    
    def __init__(self, target, ports):
        super().__init__()
        self.target = target
        self.ports = ports
        self.running = True
        
    def run(self):
        open_ports = []
        total_ports = len(self.ports)
        
        for i, port in enumerate(self.ports):
            if not self.running:
                break
                
            try:
                sock = socket.socket()
                sock.settimeout(1)
                sock.connect((self.target, port))
                open_ports.append(port)
                self.update_signal.emit("open", port, True)
                sock.close()
            except:
                self.update_signal.emit("closed", port, False)
            
            progress = int((i + 1) / total_ports * 100)
            self.progress_signal.emit(progress)
            time.sleep(0.02)  # To prevent flooding the UI
        
        self.finished_signal.emit(open_ports)
        
    def stop(self):
        self.running = False

class BruteForceThread(QThread):
    update_signal = pyqtSignal(str, bool)
    finished_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    
    def __init__(self, url, username, passwords):
        super().__init__()
        self.url = url
        self.username = username
        self.passwords = passwords
        self.running = True
        
    def run(self):
        total = len(self.passwords)
        
        for i, password in enumerate(self.passwords):
            if not self.running:
                break
                
            try:
                data = {"username": self.username, "password": password}
                response = requests.post(self.url, data=data, timeout=5)
                if "Login successful" in response.text:
                    self.update_signal.emit(f"Password found: {password}", True)
                    self.finished_signal.emit(password)
                    return
                else:
                    self.update_signal.emit(f"Tried: {password}", False)
            except Exception as e:
                self.update_signal.emit(f"Error: {str(e)}", False)
            
            progress = int((i + 1) / total * 100)
            self.progress_signal.emit(progress)
            time.sleep(0.05)
        
        self.update_signal.emit("No password found", False)
        self.finished_signal.emit(None)
        
    def stop(self):
        self.running = False

class WebScannerThread(QThread):
    update_signal = pyqtSignal(str, bool)
    finished_signal = pyqtSignal(list)
    
    def __init__(self, url):
        super().__init__()
        self.url = url
        
    def run(self):
        try:
            response = requests.get(self.url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            links = [a['href'] for a in soup.find_all('a', href=True)]
            self.finished_signal.emit(links)
        except Exception as e:
            self.update_signal.emit(f"Error: {str(e)}", False)

class HashCrackerThread(QThread):
    update_signal = pyqtSignal(str, bool)
    finished_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    
    def __init__(self, hash_to_crack, passwords):
        super().__init__()
        self.hash_to_crack = hash_to_crack
        self.passwords = passwords
        self.running = True
        
    def run(self):
        total = len(self.passwords)
        
        for i, word in enumerate(self.passwords):
            if not self.running:
                break
                
            word = word.strip()
            if hashlib.md5(word.encode()).hexdigest() == self.hash_to_crack:
                self.update_signal.emit(f"Hash cracked: {word}", True)
                self.finished_signal.emit(word)
                return
            else:
                self.update_signal.emit(f"Tried: {word}", False)
            
            progress = int((i + 1) / total * 100)
            self.progress_signal.emit(progress)
            time.sleep(0.02)
        
        self.update_signal.emit("Hash not found in wordlist", False)
        self.finished_signal.emit(None)
        
    def stop(self):
        self.running = False

# =====================
# Main Application
# =====================
class PenTestToolkit(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CyberScan Pro - Penetration Testing Toolkit")
        self.setGeometry(100, 100, 1000, 750)
        
        # Apply dark theme
        self.set_dark_theme()
        
        # Create main tabs
        self.tab_widget = QTabWidget()
        self.tab_widget.setDocumentMode(True)
        self.tab_widget.setTabPosition(QTabWidget.North)
        self.tab_widget.setMovable(False)
        self.setCentralWidget(self.tab_widget)
        
        # Create tabs
        self.port_scanner_tab = self.create_port_scanner_tab()
        self.brute_force_tab = self.create_brute_force_tab()
        self.web_scanner_tab = self.create_web_scanner_tab()
        self.hash_cracker_tab = self.create_hash_cracker_tab()
        
        # Add tabs to widget
        self.tab_widget.addTab(self.port_scanner_tab, "Port Scanner")
        self.tab_widget.addTab(self.brute_force_tab, "Brute Force")
        self.tab_widget.addTab(self.web_scanner_tab, "Web Scanner")
        self.tab_widget.addTab(self.hash_cracker_tab, "Hash Cracker")
        
        # Initialize worker threads
        self.port_scanner_thread = None
        self.brute_force_thread = None
        self.web_scanner_thread = None
        self.hash_cracker_thread = None
        
        # Status bar
        self.status_bar = QStatusBar()
        self.status_bar.setFont(QFont("Segoe UI", 9))
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Create header
        self.create_header()
        
    def create_header(self):
        header = QWidget()
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(20, 15, 20, 15)
        
        title = QLabel("CyberScan Pro")
        title_font = QFont("Segoe UI", 16, QFont.Bold)
        title_font.setLetterSpacing(QFont.AbsoluteSpacing, 1)
        title.setFont(title_font)
        title.setStyleSheet("color: #5dade2;")
        
        subtitle = QLabel("Penetration Testing Toolkit")
        subtitle_font = QFont("Segoe UI", 10)
        subtitle_font.setItalic(True)
        subtitle.setFont(subtitle_font)
        subtitle.setStyleSheet("color: #aeb6bf;")
        
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        header_layout.addStretch()
        
        # System status indicator
        status_indicator = QLabel("●")
        status_indicator.setFont(QFont("Segoe UI", 12))
        status_indicator.setStyleSheet("color: #58d68d;")
        status_indicator.setToolTip("System Status: Operational")
        
        header_layout.addWidget(status_indicator)
        header.setLayout(header_layout)
        header.setStyleSheet("background-color: #1c2833; border-bottom: 1px solid #2c3e50;")
        
        # Add to main layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(header)
        main_layout.addWidget(self.tab_widget)
        
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)
    
    def set_dark_theme(self):
        # Set modern dark theme
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(28, 34, 41))
        dark_palette.setColor(QPalette.WindowText, QColor(220, 220, 220))
        dark_palette.setColor(QPalette.Base, QColor(35, 43, 53))
        dark_palette.setColor(QPalette.AlternateBase, QColor(44, 53, 63))
        dark_palette.setColor(QPalette.ToolTipBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipText, Qt.white)
        dark_palette.setColor(QPalette.Text, QColor(220, 220, 220))
        dark_palette.setColor(QPalette.Button, QColor(44, 53, 63))
        dark_palette.setColor(QPalette.ButtonText, Qt.white)
        dark_palette.setColor(QPalette.BrightText, Qt.red)
        dark_palette.setColor(QPalette.Highlight, QColor(65, 131, 215))
        dark_palette.setColor(QPalette.HighlightedText, Qt.white)
        dark_palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(127, 127, 127))
        
        app.setPalette(dark_palette)
        app.setStyleSheet("""
            QMainWindow {
                background-color: #1c2833;
            }
            QTabWidget {
                background: transparent;
                border: none;
            }
            QTabWidget::pane {
                border: none;
                background: #1c2833;
                margin-top: 10px;
            }
            QTabBar::tab {
                background: #2c3e50;
                color: #ecf0f1;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background: #3498db;
                color: white;
                border-bottom: 2px solid #2980b9;
            }
            QTabBar::tab:hover {
                background: #2980b9;
            }
            QGroupBox {
                border: 1px solid #2c3e50;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 15px;
                font-weight: bold;
                color: #3498db;
                background-color: rgba(44, 62, 80, 0.3);
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLabel {
                color: #ecf0f1;
            }
            QLineEdit, QTextEdit, QComboBox, QListWidget {
                background-color: #2c3e50;
                color: #ecf0f1;
                border: 1px solid #34495e;
                border-radius: 4px;
                padding: 5px;
                selection-background-color: #3498db;
            }
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
                border: 1px solid #3498db;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #1c6ea4;
            }
            QPushButton:disabled {
                background-color: #34495e;
                color: #7f8c8d;
            }
            QProgressBar {
                border: 1px solid #34495e;
                border-radius: 4px;
                background: #2c3e50;
                text-align: center;
                height: 16px;
            }
            QProgressBar::chunk {
                background: #3498db;
                border-radius: 3px;
            }
            QListWidget {
                background-color: #2c3e50;
                alternate-background-color: #34495e;
            }
            QListWidget::item {
                padding: 5px;
            }
            QListWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
            QTextEdit {
                font-family: 'Consolas', 'Courier New', monospace;
            }
            QStatusBar {
                background-color: #1c2833;
                color: #bdc3c7;
                border-top: 1px solid #2c3e50;
                padding: 5px;
                font-size: 9pt;
            }
        """)
        
        # Set tooltip style
        app.setStyleSheet(app.styleSheet() + """
            QToolTip {
                background-color: #2c3e50;
                color: #ecf0f1;
                border: 1px solid #3498db;
                padding: 5px;
                border-radius: 3px;
                opacity: 230;
            }
        """)
        
        # Set monospace font for output areas
        fixed_font = QFont("Consolas", 10)
        fixed_font.setStyleHint(QFont.Monospace)
        app.setFont(fixed_font, "QTextEdit")

    # =====================
    # Tab Creation Methods
    # =====================
    def create_port_scanner_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        # Input Group
        input_group = QGroupBox("Scan Configuration")
        input_layout = QGridLayout()
        input_layout.setColumnStretch(1, 1)
        input_layout.setColumnStretch(3, 1)
        
        input_layout.addWidget(QLabel("Target:"), 0, 0)
        self.target_input = QLineEdit("127.0.0.1")
        self.target_input.setPlaceholderText("IP Address or Domain")
        self.target_input.setToolTip("Enter the target IP address or domain name to scan")
        input_layout.addWidget(self.target_input, 0, 1, 1, 3)
        
        input_layout.addWidget(QLabel("Ports:"), 1, 0)
        self.port_input = QComboBox()
        self.port_input.addItems([
            "Common Ports (21,22,23,80,443)",
            "Top 100 Ports",
            "Custom Ports..."
        ])
        self.port_input.setToolTip("Select the port range to scan")
        input_layout.addWidget(self.port_input, 1, 1)
        
        self.custom_port_input = QLineEdit()
        self.custom_port_input.setPlaceholderText("Enter ports (comma separated)")
        self.custom_port_input.setVisible(False)
        self.custom_port_input.setToolTip("Enter custom ports separated by commas (e.g., 80,443,8080)")
        input_layout.addWidget(self.custom_port_input, 1, 2, 1, 2)
        
        self.port_input.currentIndexChanged.connect(lambda i: 
            self.custom_port_input.setVisible(i == 2))
        
        # Buttons
        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.setIcon(QIcon.fromTheme("system-search"))
        self.scan_button.setToolTip("Start port scanning")
        self.scan_button.clicked.connect(self.start_port_scan)
        button_layout.addWidget(self.scan_button)
        
        input_layout.addLayout(button_layout, 2, 0, 1, 4)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Results Group
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout()
        
        # Port list
        port_list_frame = QFrame()
        port_list_layout = QVBoxLayout(port_list_frame)
        port_list_layout.setContentsMargins(0, 0, 0, 0)
        
        port_list_layout.addWidget(QLabel("Open Ports:"))
        self.port_list = QListWidget()
        self.port_list.setStyleSheet("""
            QListWidget {
                background-color: #2c3e50;
                border: 1px solid #34495e;
                border-radius: 4px;
            }
        """)
        port_list_layout.addWidget(self.port_list)
        
        # Output console
        output_frame = QFrame()
        output_layout = QVBoxLayout(output_frame)
        output_layout.setContentsMargins(0, 0, 0, 0)
        
        output_layout.addWidget(QLabel("Scan Log:"))
        self.port_output = QTextEdit()
        self.port_output.setReadOnly(True)
        self.port_output.setMinimumHeight(100)
        output_layout.addWidget(self.port_output)
        
        # Splitter for results
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(port_list_frame)
        splitter.addWidget(output_frame)
        splitter.setSizes([300, 150])
        results_layout.addWidget(splitter)
        
        # Progress bar
        progress_layout = QHBoxLayout()
        progress_layout.addWidget(QLabel("Progress:"))
        self.port_progress = QProgressBar()
        self.port_progress.setRange(0, 100)
        self.port_progress.setTextVisible(True)
        progress_layout.addWidget(self.port_progress)
        results_layout.addLayout(progress_layout)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group, 1)
        
        return tab

    def create_brute_force_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        # Input Group
        input_group = QGroupBox("Brute Force Configuration")
        input_layout = QGridLayout()
        input_layout.setColumnStretch(1, 1)
        
        input_layout.addWidget(QLabel("Login URL:"), 0, 0)
        self.url_input = QLineEdit("http://example.com/login")
        self.url_input.setToolTip("URL of the login page to attack")
        input_layout.addWidget(self.url_input, 0, 1)
        
        input_layout.addWidget(QLabel("Username:"), 1, 0)
        self.username_input = QLineEdit("admin")
        self.username_input.setToolTip("Username to use for the attack")
        input_layout.addWidget(self.username_input, 1, 1)
        
        input_layout.addWidget(QLabel("Passwords:"), 2, 0, 1, 2)
        self.password_input = QTextEdit()
        self.password_input.setPlaceholderText("Enter passwords (one per line)")
        self.password_input.setMinimumHeight(120)
        self.password_input.setToolTip("List of passwords to try, one per line")
        input_layout.addWidget(self.password_input, 3, 0, 1, 2)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.load_passwords_button = QPushButton("Load Passwords")
        self.load_passwords_button.setIcon(QIcon.fromTheme("document-open"))
        self.load_passwords_button.setToolTip("Load passwords from a text file")
        self.load_passwords_button.clicked.connect(self.load_passwords)
        button_layout.addWidget(self.load_passwords_button)
        
        self.brute_force_button = QPushButton("Start Attack")
        self.brute_force_button.setIcon(QIcon.fromTheme("system-run"))
        self.brute_force_button.setToolTip("Start the brute force attack")
        self.brute_force_button.clicked.connect(self.start_brute_force)
        button_layout.addWidget(self.brute_force_button)
        
        input_layout.addLayout(button_layout, 4, 0, 1, 2)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Results Group
        results_group = QGroupBox("Attack Results")
        results_layout = QVBoxLayout()
        
        results_layout.addWidget(QLabel("Output:"))
        self.brute_output = QTextEdit()
        self.brute_output.setReadOnly(True)
        self.brute_output.setMinimumHeight(200)
        results_layout.addWidget(self.brute_output)
        
        # Progress bar
        progress_layout = QHBoxLayout()
        progress_layout.addWidget(QLabel("Progress:"))
        self.brute_progress = QProgressBar()
        self.brute_progress.setRange(0, 100)
        self.brute_progress.setTextVisible(True)
        progress_layout.addWidget(self.brute_progress)
        results_layout.addLayout(progress_layout)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group, 1)
        
        return tab

    def create_web_scanner_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        # Input Group
        input_group = QGroupBox("Web Scanner Configuration")
        input_layout = QHBoxLayout()
        
        input_layout.addWidget(QLabel("URL:"))
        self.web_url_input = QLineEdit("http://example.com")
        self.web_url_input.setToolTip("URL of the website to scan for links")
        input_layout.addWidget(self.web_url_input, 1)
        
        self.web_scan_button = QPushButton("Scan Links")
        self.web_scan_button.setIcon(QIcon.fromTheme("edit-find"))
        self.web_scan_button.setToolTip("Scan the website for links")
        self.web_scan_button.clicked.connect(self.start_web_scan)
        input_layout.addWidget(self.web_scan_button)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Results Group
        results_group = QGroupBox("Scan Results")
        results_layout = QVBoxLayout()
        
        results_layout.addWidget(QLabel("Found Links:"))
        self.link_list = QListWidget()
        self.link_list.setStyleSheet("""
            QListWidget {
                background-color: #2c3e50;
                border: 1px solid #34495e;
                border-radius: 4px;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #34495e;
            }
            QListWidget::item:selected {
                background-color: #3498db;
                color: white;
            }
        """)
        results_layout.addWidget(self.link_list)
        
        # Status
        status_layout = QHBoxLayout()
        self.link_count_label = QLabel("Links found: 0")
        self.link_count_label.setStyleSheet("font-style: italic; color: #bdc3c7;")
        status_layout.addWidget(self.link_count_label)
        status_layout.addStretch()
        
        self.copy_button = QPushButton("Copy All")
        self.copy_button.setIcon(QIcon.fromTheme("edit-copy"))
        self.copy_button.setToolTip("Copy all links to clipboard")
        self.copy_button.clicked.connect(self.copy_links)
        status_layout.addWidget(self.copy_button)
        
        results_layout.addLayout(status_layout)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group, 1)
        
        return tab

    def create_hash_cracker_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        # Input Group
        input_group = QGroupBox("Hash Cracker Configuration")
        input_layout = QGridLayout()
        input_layout.setColumnStretch(1, 1)
        
        input_layout.addWidget(QLabel("MD5 Hash:"), 0, 0)
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Enter 32-character MD5 hash")
        self.hash_input.setToolTip("Enter the MD5 hash to crack (32 hexadecimal characters)")
        input_layout.addWidget(self.hash_input, 0, 1)
        
        input_layout.addWidget(QLabel("Wordlist:"), 1, 0, 1, 2)
        self.wordlist_input = QTextEdit()
        self.wordlist_input.setPlaceholderText("Enter words to try (one per line)")
        self.wordlist_input.setMinimumHeight(120)
        self.wordlist_input.setToolTip("List of words to try as possible passwords")
        input_layout.addWidget(self.wordlist_input, 2, 0, 1, 2)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.load_wordlist_button = QPushButton("Load Wordlist")
        self.load_wordlist_button.setIcon(QIcon.fromTheme("document-open"))
        self.load_wordlist_button.setToolTip("Load a wordlist from a text file")
        self.load_wordlist_button.clicked.connect(self.load_wordlist)
        button_layout.addWidget(self.load_wordlist_button)
        
        self.crack_button = QPushButton("Crack Hash")
        self.crack_button.setIcon(QIcon.fromTheme("system-run"))
        self.crack_button.setToolTip("Start cracking the hash")
        self.crack_button.clicked.connect(self.start_hash_cracker)
        button_layout.addWidget(self.crack_button)
        
        input_layout.addLayout(button_layout, 3, 0, 1, 2)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Results Group
        results_group = QGroupBox("Cracking Results")
        results_layout = QVBoxLayout()
        
        results_layout.addWidget(QLabel("Output:"))
        self.hash_output = QTextEdit()
        self.hash_output.setReadOnly(True)
        self.hash_output.setMinimumHeight(200)
        results_layout.addWidget(self.hash_output)
        
        # Progress bar
        progress_layout = QHBoxLayout()
        progress_layout.addWidget(QLabel("Progress:"))
        self.hash_progress = QProgressBar()
        self.hash_progress.setRange(0, 100)
        self.hash_progress.setTextVisible(True)
        progress_layout.addWidget(self.hash_progress)
        results_layout.addLayout(progress_layout)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group, 1)
        
        return tab

    # =====================
    # Utility Methods
    # =====================
    def append_output(self, text_widget, text, success=False):
        if success:
            text_widget.setTextColor(QColor("#58d68d"))  # Green for success
        else:
            text_widget.setTextColor(QColor("#e74c3c"))  # Red for errors/failures
        
        text_widget.append(text)
        text_widget.moveCursor(QTextCursor.End)
        
        if success:
            text_widget.setTextColor(QColor("#ecf0f1"))  # Reset to default

    def load_passwords(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Password File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    passwords = f.read()
                    self.password_input.setPlainText(passwords)
                    self.status_bar.showMessage(f"Loaded passwords from {file_path}")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not read file: {str(e)}")

    def load_wordlist(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Wordlist File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    wordlist = f.read()
                    self.wordlist_input.setPlainText(wordlist)
                    self.status_bar.showMessage(f"Loaded wordlist from {file_path}")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not read file: {str(e)}")
    
    def copy_links(self):
        links = [self.link_list.item(i).text() for i in range(self.link_list.count())]
        if links:
            clipboard = QApplication.clipboard()
            clipboard.setText("\n".join(links))
            self.status_bar.showMessage(f"Copied {len(links)} links to clipboard")
        else:
            self.status_bar.showMessage("No links to copy")

    # =====================
    # Tool Execution Methods
    # =====================
    def start_port_scan(self):
        target = self.target_input.text().strip()
        
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target IP or domain")
            return
            
        if not validate_ip(target) and not validate_url(target):
            QMessageBox.warning(self, "Input Error", "Please enter a valid IP address or domain")
            return
            
        # Get ports to scan
        port_option = self.port_input.currentIndex()
        if port_option == 0:  # Common ports
            ports = [21, 22, 23, 80, 443, 8080, 8443]
        elif port_option == 1:  # Top 100 ports
            ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 
                143, 443, 445, 993, 995, 1723, 3306, 3389, 
                5900, 8080, 8443
            ]
        else:  # Custom ports
            custom_ports = self.custom_port_input.text().strip()
            if not custom_ports:
                QMessageBox.warning(self, "Input Error", "Please enter ports to scan")
                return
                
            try:
                ports = [int(p.strip()) for p in custom_ports.split(',')]
            except:
                QMessageBox.warning(self, "Input Error", "Invalid port format. Use comma-separated integers")
                return
        
        # Clear previous results
        self.port_list.clear()
        self.port_output.clear()
        
        # Update UI
        self.scan_button.setText("Stop Scan")
        self.scan_button.setIcon(QIcon.fromTheme("process-stop"))
        self.scan_button.clicked.disconnect()
        self.scan_button.clicked.connect(self.stop_port_scan)
        self.port_progress.setValue(0)
        
        # Start thread
        self.port_scanner_thread = PortScannerThread(target, ports)
        self.port_scanner_thread.update_signal.connect(self.update_port_scan)
        self.port_scanner_thread.finished_signal.connect(self.finish_port_scan)
        self.port_scanner_thread.progress_signal.connect(self.port_progress.setValue)
        self.port_scanner_thread.start()
        
        self.status_bar.showMessage(f"Scanning {target}...")
        
    def update_port_scan(self, status, port, is_open):
        if is_open:
            self.port_list.addItem(f"Port {port} [OPEN]")
            self.append_output(self.port_output, f"[+] Port {port} is open", True)
        else:
            self.append_output(self.port_output, f"[-] Port {port} is closed", False)
    
    def finish_port_scan(self, open_ports):
        self.scan_button.setText("Start Scan")
        self.scan_button.setIcon(QIcon.fromTheme("system-search"))
        self.scan_button.clicked.disconnect()
        self.scan_button.clicked.connect(self.start_port_scan)
        
        if open_ports:
            self.status_bar.showMessage(f"Scan completed! Found {len(open_ports)} open ports.")
            self.append_output(self.port_output, "\n[+] Scan completed successfully!", True)
        else:
            self.status_bar.showMessage("Scan completed! No open ports found.")
            self.append_output(self.port_output, "\n[-] No open ports found.", False)
    
    def stop_port_scan(self):
        if self.port_scanner_thread:
            self.port_scanner_thread.stop()
            self.port_scanner_thread.wait()
            self.scan_button.setText("Start Scan")
            self.scan_button.setIcon(QIcon.fromTheme("system-search"))
            self.scan_button.clicked.disconnect()
            self.scan_button.clicked.connect(self.start_port_scan)
            self.status_bar.showMessage("Port scan stopped by user")

    def start_brute_force(self):
        url = self.url_input.text().strip()
        username = self.username_input.text().strip()
        passwords = self.password_input.toPlainText().splitlines()
        
        if not url or not validate_url(url):
            QMessageBox.warning(self, "Input Error", "Please enter a valid URL")
            return
            
        if not username:
            QMessageBox.warning(self, "Input Error", "Please enter a username")
            return
            
        if not passwords:
            QMessageBox.warning(self, "Input Error", "Please enter at least one password")
            return
            
        # Update UI
        self.brute_output.clear()
        self.brute_force_button.setText("Stop Attack")
        self.brute_force_button.setIcon(QIcon.fromTheme("process-stop"))
        self.brute_force_button.clicked.disconnect()
        self.brute_force_button.clicked.connect(self.stop_brute_force)
        self.brute_progress.setValue(0)
        
        # Start thread
        self.brute_force_thread = BruteForceThread(url, username, passwords)
        self.brute_force_thread.update_signal.connect(
            lambda text, success: self.append_output(self.brute_output, text, success)
        )
        self.brute_force_thread.finished_signal.connect(self.finish_brute_force)
        self.brute_force_thread.progress_signal.connect(self.brute_progress.setValue)
        self.brute_force_thread.start()
        
        self.status_bar.showMessage(f"Brute forcing {url}...")
        
    def finish_brute_force(self, password):
        self.brute_force_button.setText("Start Attack")
        self.brute_force_button.setIcon(QIcon.fromTheme("system-run"))
        self.brute_force_button.clicked.disconnect()
        self.brute_force_button.clicked.connect(self.start_brute_force)
        
        if password:
            self.status_bar.showMessage(f"Password found: {password}")
        else:
            self.status_bar.showMessage("Password not found")
    
    def stop_brute_force(self):
        if self.brute_force_thread:
            self.brute_force_thread.stop()
            self.brute_force_thread.wait()
            self.brute_force_button.setText("Start Attack")
            self.brute_force_button.setIcon(QIcon.fromTheme("system-run"))
            self.brute_force_button.clicked.disconnect()
            self.brute_force_button.clicked.connect(self.start_brute_force)
            self.status_bar.showMessage("Brute force attack stopped by user")

    def start_web_scan(self):
        url = self.web_url_input.text().strip()
        
        if not url or not validate_url(url):
            QMessageBox.warning(self, "Input Error", "Please enter a valid URL")
            return
            
        # Update UI
        self.link_list.clear()
        self.link_count_label.setText("Links found: 0")
        self.web_scan_button.setEnabled(False)
        self.web_scan_button.setText("Scanning...")
        
        # Start thread
        self.web_scanner_thread = WebScannerThread(url)
        self.web_scanner_thread.update_signal.connect(
            lambda text, success: QMessageBox.warning(self, "Error", text)
        )
        self.web_scanner_thread.finished_signal.connect(self.finish_web_scan)
        self.web_scanner_thread.start()
        
        self.status_bar.showMessage(f"Scanning {url}...")
        
    def finish_web_scan(self, links):
        self.web_scan_button.setEnabled(True)
        self.web_scan_button.setText("Scan Links")
        
        if links:
            self.link_list.addItems(links)
            self.link_count_label.setText(f"Links found: {len(links)}")
            self.status_bar.showMessage(f"Found {len(links)} links")
        else:
            self.status_bar.showMessage("No links found")

    def start_hash_cracker(self):
        hash_str = self.hash_input.text().strip()
        words = self.wordlist_input.toPlainText().splitlines()
        
        if not hash_str or not validate_hash(hash_str):
            QMessageBox.warning(self, "Input Error", "Please enter a valid 32-character MD5 hash")
            return
            
        if not words:
            QMessageBox.warning(self, "Input Error", "Please enter at least one word to try")
            return
            
        # Update UI
        self.hash_output.clear()
        self.crack_button.setText("Stop Cracking")
        self.crack_button.setIcon(QIcon.fromTheme("process-stop"))
        self.crack_button.clicked.disconnect()
        self.crack_button.clicked.connect(self.stop_hash_cracker)
        self.hash_progress.setValue(0)
        
        # Start thread
        self.hash_cracker_thread = HashCrackerThread(hash_str, words)
        self.hash_cracker_thread.update_signal.connect(
            lambda text, success: self.append_output(self.hash_output, text, success)
        )
        self.hash_cracker_thread.finished_signal.connect(self.finish_hash_cracker)
        self.hash_cracker_thread.progress_signal.connect(self.hash_progress.setValue)
        self.hash_cracker_thread.start()
        
        self.status_bar.showMessage(f"Cracking hash: {hash_str}...")
        
    def finish_hash_cracker(self, result):
        self.crack_button.setText("Crack Hash")
        self.crack_button.setIcon(QIcon.fromTheme("system-run"))
        self.crack_button.clicked.disconnect()
        self.crack_button.clicked.connect(self.start_hash_cracker)
        
        if result:
            self.status_bar.showMessage(f"Hash cracked: {result}")
        else:
            self.status_bar.showMessage("Hash not cracked")
    
    def stop_hash_cracker(self):
        if self.hash_cracker_thread:
            self.hash_cracker_thread.stop()
            self.hash_cracker_thread.wait()
            self.crack_button.setText("Crack Hash")
            self.crack_button.setIcon(QIcon.fromTheme("system-run"))
            self.crack_button.clicked.disconnect()
            self.crack_button.clicked.connect(self.start_hash_cracker)
            self.status_bar.showMessage("Hash cracking stopped by user")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Segoe UI", 10))
    
    # Set style based on OS
    if platform.system() == "Windows":
        app.setStyle("Fusion")
    elif platform.system() == "Darwin":  # macOS
        app.setStyle("macintosh")
    else:  # Linux and other systems
        app.setStyle("Fusion")
    
    window = PenTestToolkit()
    window.show()
    sys.exit(app.exec_())