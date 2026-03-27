import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from cyber_toolkit.config import APP_NAME, DATA_DIR, VAULT_FILE
from cyber_toolkit.modules.attack_simulator import AttackSimulator
from cyber_toolkit.modules.file_crypto import FileCipher
from cyber_toolkit.modules.monitor import ConnectionMonitor
from cyber_toolkit.modules.password_manager import PasswordVault
from cyber_toolkit.modules.scanner import NetworkScanner


class ToolkitApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1180x760")
        self.minsize(1000, 680)
        self.configure(bg="#0c0f10")

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.scanner = NetworkScanner()
        self.monitor = ConnectionMonitor()
        self.vault = PasswordVault(VAULT_FILE)
        self.file_cipher = FileCipher()
        self.simulator = AttackSimulator()

        self._build_style()
        self._build_ui()

    def _build_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#0c0f10")
        style.configure("TLabel", background="#0c0f10", foreground="#c6f7d0")
        style.configure("Header.TLabel", font=("Consolas", 18, "bold"), foreground="#5eff9a")
        style.configure("TButton", background="#17322c", foreground="#c6f7d0")
        style.configure("Treeview", background="#111517", fieldbackground="#111517", foreground="#d7fbe1")
        style.configure("Treeview.Heading", background="#17322c", foreground="#8fffbb", font=("Consolas", 10, "bold"))

    def _build_ui(self) -> None:
        header = ttk.Label(self, text="CyberSecurity Toolkit - All in One", style="Header.TLabel")
        header.pack(anchor="w", padx=14, pady=(12, 6))

        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(self, textvariable=self.status_var)
        status.pack(anchor="w", padx=14, pady=(0, 8))

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=12, pady=8)

        self.dashboard_tab = ttk.Frame(notebook)
        self.scanner_tab = ttk.Frame(notebook)
        self.monitor_tab = ttk.Frame(notebook)
        self.vault_tab = ttk.Frame(notebook)
        self.file_tab = ttk.Frame(notebook)
        self.sim_tab = ttk.Frame(notebook)

        notebook.add(self.dashboard_tab, text="Dashboard")
        notebook.add(self.scanner_tab, text="Scanner")
        notebook.add(self.monitor_tab, text="Connections")
        notebook.add(self.vault_tab, text="Password Vault")
        notebook.add(self.file_tab, text="File Encryptor")
        notebook.add(self.sim_tab, text="Ethical Simulator")

        self._build_dashboard()
        self._build_scanner()
        self._build_monitor()
        self._build_vault()
        self._build_file_encryptor()
        self._build_simulator()

    def _build_dashboard(self) -> None:
        frame = self.dashboard_tab
        frame.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

        self.metric_networks = tk.StringVar(value="WiFi networks: -")
        self.metric_devices = tk.StringVar(value="Local devices: -")
        self.metric_connections = tk.StringVar(value="Connections: -")
        self.metric_vault = tk.StringVar(value="Vault entries: -")

        labels = [
            self.metric_networks,
            self.metric_devices,
            self.metric_connections,
            self.metric_vault,
        ]
        for index, var in enumerate(labels):
            lbl = ttk.Label(frame, textvariable=var, font=("Consolas", 13, "bold"))
            lbl.grid(row=index // 2, column=index % 2, sticky="w", padx=20, pady=16)

        refresh_btn = ttk.Button(frame, text="Refresh Dashboard", command=self.refresh_dashboard)
        refresh_btn.grid(row=3, column=0, padx=20, pady=12, sticky="w")

        note = ttk.Label(
            frame,
            text="Ethical mode: this toolkit visualizes and protects assets, it does not perform intrusive attacks.",
        )
        note.grid(row=4, column=0, columnspan=2, padx=20, pady=10, sticky="w")

    def _build_scanner(self) -> None:
        frame = self.scanner_tab
        ttk.Button(frame, text="Scan WiFi", command=self.scan_wifi).pack(anchor="w", padx=10, pady=(10, 4))
        self.wifi_tree = ttk.Treeview(frame, columns=("ssid", "bssid", "security", "signal"), show="headings", height=8)
        for col in ("ssid", "bssid", "security", "signal"):
            self.wifi_tree.heading(col, text=col.upper())
            self.wifi_tree.column(col, width=220)
        self.wifi_tree.pack(fill="x", padx=10)

        ttk.Button(frame, text="Scan Local Devices", command=self.scan_devices).pack(anchor="w", padx=10, pady=(14, 4))
        self.device_tree = ttk.Treeview(frame, columns=("ip", "mac"), show="headings", height=10)
        for col in ("ip", "mac"):
            self.device_tree.heading(col, text=col.upper())
            self.device_tree.column(col, width=300)
        self.device_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _build_monitor(self) -> None:
        frame = self.monitor_tab
        ttk.Button(frame, text="Refresh Connections", command=self.refresh_connections).pack(anchor="w", padx=10, pady=10)
        cols = ("pid", "process", "local", "remote", "status", "risk")
        self.conn_tree = ttk.Treeview(frame, columns=cols, show="headings", height=20)
        for col in cols:
            self.conn_tree.heading(col, text=col.upper())
            self.conn_tree.column(col, width=170)
        self.conn_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _build_vault(self) -> None:
        frame = self.vault_tab

        form = ttk.Frame(frame)
        form.pack(fill="x", padx=10, pady=10)

        ttk.Label(form, text="Master password:").grid(row=0, column=0, sticky="w", padx=4, pady=4)
        self.vault_master_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.vault_master_var, show="*").grid(row=0, column=1, sticky="ew", padx=4, pady=4)

        ttk.Label(form, text="Service:").grid(row=1, column=0, sticky="w", padx=4, pady=4)
        self.service_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.service_var).grid(row=1, column=1, sticky="ew", padx=4, pady=4)

        ttk.Label(form, text="Username:").grid(row=2, column=0, sticky="w", padx=4, pady=4)
        self.username_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.username_var).grid(row=2, column=1, sticky="ew", padx=4, pady=4)

        ttk.Label(form, text="Password:").grid(row=3, column=0, sticky="w", padx=4, pady=4)
        self.password_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.password_var).grid(row=3, column=1, sticky="ew", padx=4, pady=4)

        form.columnconfigure(1, weight=1)

        btns = ttk.Frame(frame)
        btns.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(btns, text="Init Vault", command=self.init_vault).pack(side="left", padx=4)
        ttk.Button(btns, text="Generate Password", command=self.generate_password).pack(side="left", padx=4)
        ttk.Button(btns, text="Save Entry", command=self.save_entry).pack(side="left", padx=4)
        ttk.Button(btns, text="Load Entries", command=self.load_entries).pack(side="left", padx=4)

        self.vault_tree = ttk.Treeview(frame, columns=("service", "username", "password", "created_at"), show="headings", height=14)
        for col in ("service", "username", "password", "created_at"):
            self.vault_tree.heading(col, text=col.upper())
            self.vault_tree.column(col, width=250)
        self.vault_tree.pack(fill="both", expand=True, padx=10, pady=(0, 12))

    def _build_file_encryptor(self) -> None:
        frame = self.file_tab

        self.file_path_var = tk.StringVar()
        self.file_key_var = tk.StringVar()

        row1 = ttk.Frame(frame)
        row1.pack(fill="x", padx=12, pady=(14, 8))
        ttk.Label(row1, text="File:").pack(side="left")
        ttk.Entry(row1, textvariable=self.file_path_var).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(row1, text="Browse", command=self.select_file).pack(side="left")

        row2 = ttk.Frame(frame)
        row2.pack(fill="x", padx=12, pady=8)
        ttk.Label(row2, text="Key / password:").pack(side="left")
        ttk.Entry(row2, textvariable=self.file_key_var, show="*").pack(side="left", fill="x", expand=True, padx=8)

        row3 = ttk.Frame(frame)
        row3.pack(fill="x", padx=12, pady=8)
        ttk.Button(row3, text="Encrypt", command=self.encrypt_file).pack(side="left", padx=4)
        ttk.Button(row3, text="Decrypt", command=self.decrypt_file).pack(side="left", padx=4)

    def _build_simulator(self) -> None:
        frame = self.sim_tab

        self.sim_length = tk.IntVar(value=10)
        self.sim_charset = tk.IntVar(value=72)
        self.sim_attempts = tk.IntVar(value=100000)
        self.sim_password = tk.StringVar(value="")

        ttk.Label(frame, text="Password length:").grid(row=0, column=0, sticky="w", padx=10, pady=8)
        ttk.Entry(frame, textvariable=self.sim_length).grid(row=0, column=1, sticky="ew", padx=8, pady=8)

        ttk.Label(frame, text="Charset size:").grid(row=1, column=0, sticky="w", padx=10, pady=8)
        ttk.Entry(frame, textvariable=self.sim_charset).grid(row=1, column=1, sticky="ew", padx=8, pady=8)

        ttk.Label(frame, text="Attempts / second:").grid(row=2, column=0, sticky="w", padx=10, pady=8)
        ttk.Entry(frame, textvariable=self.sim_attempts).grid(row=2, column=1, sticky="ew", padx=8, pady=8)

        ttk.Label(frame, text="Analyze password:").grid(row=3, column=0, sticky="w", padx=10, pady=8)
        ttk.Entry(frame, textvariable=self.sim_password, show="*").grid(row=3, column=1, sticky="ew", padx=8, pady=8)

        ttk.Button(frame, text="Run Simulation", command=self.run_simulation).grid(row=4, column=0, padx=10, pady=10, sticky="w")
        self.sim_output = tk.Text(frame, height=12, bg="#101415", fg="#99ffbf", insertbackground="#99ffbf")
        self.sim_output.grid(row=5, column=0, columnspan=2, sticky="nsew", padx=10, pady=(0, 12))

        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(5, weight=1)

    def _set_status(self, message: str) -> None:
        self.status_var.set(message)

    @staticmethod
    def _clear_tree(tree: ttk.Treeview) -> None:
        for item in tree.get_children():
            tree.delete(item)

    def refresh_dashboard(self) -> None:
        self.metric_networks.set(f"WiFi networks: {len(self.wifi_tree.get_children())}")
        self.metric_devices.set(f"Local devices: {len(self.device_tree.get_children())}")
        self.metric_connections.set(f"Connections: {len(self.conn_tree.get_children())}")
        self.metric_vault.set(f"Vault entries: {len(self.vault_tree.get_children())}")
        self._set_status("Dashboard updated")

    def scan_wifi(self) -> None:
        def task() -> None:
            self._set_status("Scanning WiFi networks...")
            rows = self.scanner.scan_wifi_networks()
            self.after(0, self._render_wifi, rows)

        threading.Thread(target=task, daemon=True).start()

    def _render_wifi(self, rows) -> None:
        self._clear_tree(self.wifi_tree)
        for row in rows:
            self.wifi_tree.insert("", "end", values=(row["ssid"], row["bssid"], row["security"], row["signal"]))
        self._set_status(f"WiFi scan complete ({len(rows)} networks)")
        self.refresh_dashboard()

    def scan_devices(self) -> None:
        def task() -> None:
            self._set_status("Scanning local devices...")
            rows = self.scanner.scan_local_devices()
            self.after(0, self._render_devices, rows)

        threading.Thread(target=task, daemon=True).start()

    def _render_devices(self, rows) -> None:
        self._clear_tree(self.device_tree)
        for row in rows:
            self.device_tree.insert("", "end", values=(row["ip"], row["mac"]))
        self._set_status(f"Device scan complete ({len(rows)} devices)")
        self.refresh_dashboard()

    def refresh_connections(self) -> None:
        self._clear_tree(self.conn_tree)
        rows = self.monitor.list_connections()
        for row in rows:
            self.conn_tree.insert(
                "",
                "end",
                values=(row["pid"], row["process"], row["local"], row["remote"], row["status"], row["risk"]),
            )
        self._set_status(f"Connections refreshed ({len(rows)} rows)")
        self.refresh_dashboard()

    def init_vault(self) -> None:
        master = self.vault_master_var.get().strip()
        if not master:
            messagebox.showerror("Vault", "Please enter a master password.")
            return
        try:
            self.vault.initialize(master)
            messagebox.showinfo("Vault", f"Vault created at {VAULT_FILE}")
            self._set_status("Vault initialized")
        except FileExistsError:
            messagebox.showwarning("Vault", "Vault already exists.")

    def generate_password(self) -> None:
        self.password_var.set(self.vault.generate_password())
        self._set_status("Generated secure password")

    def save_entry(self) -> None:
        master = self.vault_master_var.get().strip()
        service = self.service_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        if not all([master, service, username, password]):
            messagebox.showerror("Vault", "Master password, service, username and password are required.")
            return

        try:
            if not self.vault.exists():
                self.vault.initialize(master)
            self.vault.add_entry(master, service, username, password)
            self._set_status("Entry added to vault")
            self.load_entries()
        except ValueError as exc:
            messagebox.showerror("Vault", str(exc))

    def load_entries(self) -> None:
        master = self.vault_master_var.get().strip()
        if not master:
            messagebox.showerror("Vault", "Enter master password first.")
            return
        try:
            rows = self.vault.list_entries(master)
        except (FileNotFoundError, ValueError) as exc:
            messagebox.showerror("Vault", str(exc))
            return

        self._clear_tree(self.vault_tree)
        for row in rows:
            self.vault_tree.insert("", "end", values=(row["service"], row["username"], row["password"], row["created_at"]))
        self._set_status(f"Loaded {len(rows)} vault entries")
        self.refresh_dashboard()

    def select_file(self) -> None:
        path = filedialog.askopenfilename(title="Select file")
        if path:
            self.file_path_var.set(path)

    def encrypt_file(self) -> None:
        path = self.file_path_var.get().strip()
        key = self.file_key_var.get().strip()
        if not path or not key:
            messagebox.showerror("Encryptor", "Choose file and key.")
            return
        try:
            target = self.file_cipher.encrypt_file(path, key)
            messagebox.showinfo("Encryptor", f"Encrypted file created: {target}")
            self._set_status("File encrypted")
        except Exception as exc:  # pragma: no cover - GUI level fallback
            messagebox.showerror("Encryptor", str(exc))

    def decrypt_file(self) -> None:
        path = self.file_path_var.get().strip()
        key = self.file_key_var.get().strip()
        if not path or not key:
            messagebox.showerror("Encryptor", "Choose encrypted file and key.")
            return
        try:
            target = self.file_cipher.decrypt_file(path, key)
            messagebox.showinfo("Encryptor", f"Decrypted file created: {target}")
            self._set_status("File decrypted")
        except Exception as exc:  # pragma: no cover - GUI level fallback
            messagebox.showerror("Encryptor", str(exc))

    def run_simulation(self) -> None:
        try:
            estimate = self.simulator.estimate(
                length=self.sim_length.get(),
                charset_size=self.sim_charset.get(),
                attempts_per_second=self.sim_attempts.get(),
            )
        except ValueError as exc:
            messagebox.showerror("Simulator", str(exc))
            return

        strength = self.simulator.password_strength(self.sim_password.get())
        out = (
            "--- Ethical brute-force estimation ---\n"
            f"Combinations: {estimate.combinations:,}\n"
            f"Entropy: {estimate.entropy_bits:.2f} bits\n"
            f"Attempts/second: {estimate.attempts_per_second:,}\n"
            f"Estimated seconds: {estimate.estimated_seconds:,.2f}\n"
            f"24h success probability: {estimate.success_probability_24h:.6f}\n\n"
            "--- Password strength ---\n"
            f"Score: {strength['score']} ({strength['label']})\n"
            f"Entropy: {strength['entropy_bits']} bits\n"
        )
        self.sim_output.delete("1.0", "end")
        self.sim_output.insert("1.0", out)
        self._set_status("Simulation complete")


def run_app() -> None:
    app = ToolkitApp()
    app.mainloop()

