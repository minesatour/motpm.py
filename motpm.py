import time
import os
import logging
import random
import threading
import queue
import sqlite3
import re
import asyncio
import ssl
import certifi
from typing import Optional
from urllib.parse import parse_qs, urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium_stealth import stealth
import mitmproxy.http
from mitmproxy import proxy, options
from mitmproxy.tools.dump import DumpMaster
from webdriver_manager.chrome import ChromeDriverManager
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# Configure logging to both file and terminal
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("otp_interception.log"), logging.StreamHandler()]
)

# Constants
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080
DATABASE = "otps.db"
TIMEOUT = 60
MITMPROXY_CA_PATH = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

# User-Agent list
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
]

# SQLite database setup
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS otps 
                 (id INTEGER PRIMARY KEY, timestamp TEXT, otp TEXT, source_url TEXT, site TEXT)''')
    conn.commit()
    conn.close()

# Random User-Agent
def random_user_agent() -> str:
    return random.choice(USER_AGENTS)

# Check mitmproxy CA certificate
def ensure_mitmproxy_ca_installed():
    return os.path.exists(MITMPROXY_CA_PATH)

# Guide for CA installation
def guide_ca_installation():
    instructions = (
        "mitmproxy CA certificate is not installed or trusted. Follow these steps:\n\n"
        "1. Run 'mitmproxy' once in a terminal to generate the CA certificate.\n"
        "2. Find the certificate at ~/.mitmproxy/mitmproxy-ca-cert.pem\n"
        "3. Install it:\n"
        "   - Windows: Double-click the .pem file, select 'Install Certificate', choose 'Trusted Root Certification Authorities'.\n"
        "   - macOS: Open Keychain Access, drag the .pem file into 'System', double-click it, set 'Trust' to 'Always Trust'.\n"
        "   - Linux: Copy to /usr/local/share/ca-certificates/, run 'sudo update-ca-certificates'.\n"
        "4. Restart your browser and rerun this script."
    )
    messagebox.showwarning("CA Certificate Required", instructions)
    return False

# Setup WebDriver with corrected ChromeDriver path
def setup_browser(proxy: bool = True) -> webdriver.Chrome:
    chrome_options = Options()
    if proxy:
        chrome_options.add_argument(f"--proxy-server={PROXY_HOST}:{PROXY_PORT}")
    chrome_options.add_argument(f"user-agent={random_user_agent()}")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument(f"--window-size={random.randint(1280, 1920)},{random.randint(720, 1080)}")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--ignore-certificate-errors")
    
    driver_base_path = ChromeDriverManager().install()
    logging.info(f"ChromeDriverManager returned base path: {driver_base_path}")
    
    expected_base_path = os.path.join(os.path.expanduser("~"), ".wdm", "drivers", "chromedriver", "linux64", "134.0.6998.88", "chromedriver-linux64")
    executable_path = os.path.join(expected_base_path, "chromedriver")
    
    if "THIRD_PARTY_NOTICES" in driver_base_path:
        logging.warning(f"ChromeDriverManager returned incorrect path: {driver_base_path}. Using expected path: {expected_base_path}")
        driver_base_path = expected_base_path
    
    executable_path = os.path.join(driver_base_path, "chromedriver")
    logging.info(f"Constructed executable path: {executable_path}")
    
    if not os.path.exists(executable_path):
        logging.error(f"File does not exist at: {executable_path}")
        raise FileNotFoundError(f"Chromedriver binary not found at {executable_path}")
    if not os.access(executable_path, os.X_OK):
        logging.warning(f"File at {executable_path} is not executable, attempting to fix permissions")
        os.chmod(executable_path, 0o755)
        logging.info(f"Permissions updated for {executable_path}")
    
    logging.info(f"Using ChromeDriver at: {executable_path}")
    service = Service(executable_path=executable_path)
    driver = webdriver.Chrome(service=service, options=chrome_options)
    
    stealth(driver, languages=["en-US", "en"], vendor="Google Inc.", platform="Win32",
            webgl_vendor="Intel Inc.", renderer="Intel Iris OpenGL Engine", fix_hairline=True)
    return driver

# OTP Interceptor with refined capture logic
class OTPInterceptor:
    def __init__(self, otp_queue: queue.Queue, gui, site: str):
        self.otp_queue = otp_queue
        self.gui = gui
        self.site = site.lower()
        self.otp_keywords = ["otp", "verification_code", "auth_code", "2fa_code", "token", "passcode", "mfa"]
        self.otp_captured = False
        self.capture_active = False  # Only capture after user activates
        self.otp_length = 6 if "paypal" in self.site else 6  # Default to 6, adjust per site
        self.otp_pattern = re.compile(fr"(?:\b|\D)(\d{{{self.otp_length}}})(?:\b|\D)")  # Site-specific length

    def start_capture(self):
        self.capture_active = True
        self.gui.log("OTP capture activated. Waiting for OTP...")

    def request(self, flow: mitmproxy.http.HTTPFlow):
        if self.capture_active and not self.otp_captured:
            otp = self.intercept_otp(flow)
            if otp:
                self.store_otp(otp, flow.request.url, flow.request.host)
                self.otp_queue.put(otp)
                self.gui.log(f"Captured OTP: {otp}")
                self.gui.display_otp(otp)
                self.otp_captured = True

    def response(self, flow: mitmproxy.http.HTTPFlow):
        if self.capture_active and not self.otp_captured and flow.response.content:
            content = flow.response.content.decode("utf-8", errors="ignore").lower()
            otp = self.extract_otp_from_content(content)
            if otp:
                self.store_otp(otp, flow.request.url, flow.request.host)
                self.otp_queue.put(otp)
                self.gui.log(f"Captured OTP: {otp}")
                self.gui.display_otp(otp)
                self.otp_captured = True

    def intercept_otp(self, flow: mitmproxy.http.HTTPFlow) -> Optional[str]:
        url = flow.request.url.lower()
        headers = str(flow.request.headers).lower()
        if any(keyword in url or keyword in headers for keyword in self.otp_keywords):
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            for param, values in query_params.items():
                if any(keyword in param.lower() for keyword in self.otp_keywords):
                    otp = values[0]
                    if self.otp_pattern.match(otp):
                        logging.info(f"Intercepted OTP from URL: {otp}")
                        return otp
        if flow.request.content:
            content = flow.request.content.decode("utf-8", errors="ignore").lower()
            if any(keyword in content for keyword in self.otp_keywords):
                return self.extract_otp_from_content(content)
        return None

    def extract_otp_from_content(self, content: str) -> Optional[str]:
        for keyword in self.otp_keywords:
            keyword_pos = content.find(keyword)
            if keyword_pos != -1:
                nearby_content = content[max(0, keyword_pos - 50):keyword_pos + 50]
                match = self.otp_pattern.search(nearby_content)
                if match:
                    otp = match.group(1)
                    logging.info(f"Extracted OTP from content: {otp}")
                    return otp
        return None

    def store_otp(self, otp: str, source_url: str, site: str):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("INSERT INTO otps (timestamp, otp, source_url, site) VALUES (datetime('now'), ?, ?, ?)",
                  (otp, source_url, site))
        conn.commit()
        conn.close()

# Run mitmproxy
def run_mitmproxy(otp_queue: queue.Queue, gui, site: str):
    async def run():
        opts = options.Options(listen_host=PROXY_HOST, listen_port=PROXY_PORT)
        master = DumpMaster(opts, with_dumper=False)
        master.addons.add(OTPInterceptor(otp_queue, gui, site))
        await master.run()
    
    threading.Thread(target=lambda: asyncio.run(run()), daemon=True).start()
    time.sleep(2)

# Enhanced GUI Class
class OTPInterceptorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("OTP Interceptor")
        self.root.geometry("700x500")
        self.root.resizable(True, True)
        self.otp_queue = queue.Queue()
        self.driver = None
        self.interceptor = None
        
        # Style configuration
        style = ttk.Style()
        style.configure("TButton", font=("Helvetica", 10))
        style.configure("TLabel", font=("Helvetica", 10))
        
        # Main frame with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # URL input section
        ttk.Label(main_frame, text="Enter Website URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.url_entry = ttk.Entry(main_frame, width=60)
        self.url_entry.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=3, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start", command=self.start_interception)
        self.start_button.grid(row=0, column=0, padx=5)
        
        self.request_otp_button = ttk.Button(button_frame, text="Request OTP", command=self.activate_otp_capture, state="disabled")
        self.request_otp_button.grid(row=0, column=1, padx=5)
        
        self.clear_button = ttk.Button(button_frame, text="Clear Log", command=self.clear_log)
        self.clear_button.grid(row=0, column=2, padx=5)
        
        self.quit_button = ttk.Button(button_frame, text="Quit", command=self.quit_app)
        self.quit_button.grid(row=0, column=3, padx=5)
        
        # Log display with label
        ttk.Label(main_frame, text="Activity Log:").grid(row=2, column=0, sticky=tk.W, pady=(5, 0))
        self.log_text = scrolledtext.ScrolledText(main_frame, width=70, height=20, wrap=tk.WORD, font=("Courier", 10))
        self.log_text.grid(row=3, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # OTP display with styled label
        self.otp_frame = ttk.LabelFrame(main_frame, text="Captured OTP", padding="5")
        self.otp_frame.grid(row=4, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=10)
        
        self.otp_label = ttk.Label(self.otp_frame, text="Waiting...", font=("Helvetica", 12, "bold"))
        self.otp_label.grid(row=0, column=0, sticky=tk.W)
        
        # Configure grid weights for resizing
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)

    def log(self, message):
        self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}\n")
        self.log_text.see(tk.END)

    def display_otp(self, otp):
        self.otp_label.config(text=otp, foreground="green")

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)
        self.log("Log cleared.")

    def quit_app(self):
        if self.driver:
            self.driver.quit()
        self.root.quit()

    def activate_otp_capture(self):
        if self.interceptor:
            self.interceptor.start_capture()
            self.request_otp_button.config(state="disabled")

    def start_interception(self):
        url = self.url_entry.get().strip()
        
        if not url:
            messagebox.showerror("Error", "Please enter a website URL.")
            return
        
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, url)
        
        # Check mitmproxy CA
        if not ensure_mitmproxy_ca_installed():
            if not guide_ca_installation():
                return
        
        self.start_button.config(state="disabled")
        self.request_otp_button.config(state="normal")
        init_db()
        run_mitmproxy(self.otp_queue, self, url)
        self.interceptor = OTPInterceptor(self.otp_queue, self, url)
        self.log("Starting OTP interception...")
        
        threading.Thread(target=self.run_script, args=(url,), daemon=True).start()

    def run_script(self, url):
        try:
            self.driver = setup_browser(proxy=True)
            self.log(f"Opening {url} in browser. Please enter your email, password, and request the OTP manually.")
            self.driver.get(url)
            
            self.log(f"Waiting for OTP... (up to {TIMEOUT} seconds)")
            try:
                otp = self.otp_queue.get(timeout=TIMEOUT)
                self.log(f"OTP captured: {otp}. Enter it manually in the browser.")
            except queue.Empty:
                self.log("No OTP captured within timeout. Check your actions or try again.")
            
            self.log("You can now interact with the account.")
        except Exception as e:
            self.log(f"Error: {str(e)}")
        finally:
            self.start_button.config(state="normal")
            self.request_otp_button.config(state="disabled")

# Main
if __name__ == "__main__":
    root = tk.Tk()
    app = OTPInterceptorGUI(root)
    root.mainloop()
