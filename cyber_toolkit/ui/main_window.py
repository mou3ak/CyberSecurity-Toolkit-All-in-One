"""CyberSecurity Toolkit — All in One  ·  Main application window.

© 2026 Sami Zi
"""

import csv as _csv
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

# ── Optional drag-and-drop ────────────────────────────────────────────────────
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    _HAS_DND = True
except Exception:
    _HAS_DND = False

from cyber_toolkit.config import APP_NAME, DATA_DIR, VAULT_FILE
from cyber_toolkit.modules.file_crypto import FileCipher
from cyber_toolkit.modules.monitor import ConnectionMonitor
from cyber_toolkit.modules.password_manager import PasswordVault
from cyber_toolkit.modules.scanner import NetworkScanner

# ── Colour palette  (GitHub dark-inspired) ───────────────────────────────────
C = {
    "bg":        "#0d1117",
    "bg2":       "#161b22",
    "card":      "#1c2128",
    "input":     "#21262d",
    "border":    "#30363d",
    "text":      "#e6edf3",
    "dim":       "#8b949e",
    "accent":    "#58a6ff",
    "green":     "#3fb950",
    "red":       "#f85149",
    "yellow":    "#d29922",
    "purple":    "#bc8cff",
    "btn":       "#21262d",
    "btn_hover": "#30363d",
}

# ── Tooltip ───────────────────────────────────────────────────────────────────

class _Tip:
    def __init__(self, w: tk.Widget, text: str) -> None:
        self._w, self._text, self._tw = w, text, None
        w.bind("<Enter>", self._show)
        w.bind("<Leave>", self._hide)
        w.bind("<ButtonPress>", self._hide)

    def _show(self, _e=None) -> None:
        x = self._w.winfo_rootx() + 10
        y = self._w.winfo_rooty() + self._w.winfo_height() + 4
        self._tw = tw = tk.Toplevel(self._w)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tk.Label(tw, text=self._text, bg=C["card"], fg=C["dim"],
                 font=("Segoe UI", 9), padx=8, pady=4,
                 highlightbackground=C["border"], highlightthickness=1).pack()

    def _hide(self, _e=None) -> None:
        if self._tw:
            self._tw.destroy()
            self._tw = None


def _tip(w: tk.Widget, text: str) -> _Tip:
    return _Tip(w, text)

# ── App root class (DnD-aware) ─────────────────────────────────────────────────
_Root = TkinterDnD.Tk if _HAS_DND else tk.Tk


class ToolkitApp(_Root):

    # ── construction ──────────────────────────────────────────────────────────

    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1280x820")
        self.minsize(1100, 720)
        self.configure(bg=C["bg"])

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.scanner    = NetworkScanner()
        self.monitor    = ConnectionMonitor()
        self.vault      = PasswordVault(VAULT_FILE)
        self.file_cipher = FileCipher()

        self._scan_rows:    list = []
        self._sort_state:   dict = {}

        self._build_style()
        self._build_ui()

    # ── style ─────────────────────────────────────────────────────────────────

    def _build_style(self) -> None:
        s = ttk.Style(self)
        s.theme_use("clam")
        # Globals
        s.configure(".", background=C["bg"], foreground=C["text"],
                    font=("Segoe UI", 10), borderwidth=0,
                    focusthickness=0, focuscolor="", troughcolor=C["bg2"])
        # Frames
        s.configure("TFrame", background=C["bg"])
        s.configure("Card.TFrame", background=C["card"])
        # Labels
        s.configure("TLabel",         background=C["bg"],   foreground=C["text"])
        s.configure("Dim.TLabel",     background=C["bg"],   foreground=C["dim"],    font=("Segoe UI", 9))
        s.configure("Header.TLabel",  background=C["bg"],   foreground=C["text"],   font=("Segoe UI", 18, "bold"))
        s.configure("Sub.TLabel",     background=C["bg"],   foreground=C["dim"],    font=("Segoe UI", 10))
        s.configure("Card.TLabel",    background=C["card"], foreground=C["text"])
        s.configure("CardDim.TLabel", background=C["card"], foreground=C["dim"],    font=("Segoe UI", 9))
        s.configure("CardBig.TLabel", background=C["card"], foreground=C["text"],   font=("Segoe UI", 30, "bold"))
        s.configure("Warn.TLabel",    background=C["bg"],   foreground=C["yellow"], font=("Segoe UI", 9))
        s.configure("OK.TLabel",      background=C["bg"],   foreground=C["green"],  font=("Segoe UI", 9))
        s.configure("Err.TLabel",     background=C["bg"],   foreground=C["red"],    font=("Segoe UI", 9))
        # Buttons
        s.configure("TButton", background=C["btn"], foreground=C["text"],
                    font=("Segoe UI", 9, "bold"), padding=(10, 5), relief="flat")
        s.map("TButton",
              background=[("active", C["btn_hover"]), ("disabled", C["bg2"])],
              foreground=[("disabled", C["dim"])])
        s.configure("Accent.TButton", background=C["accent"], foreground="#ffffff",
                    font=("Segoe UI", 9, "bold"), padding=(12, 6))
        s.map("Accent.TButton", background=[("active", "#4895ef"), ("disabled", C["bg2"])])
        s.configure("Green.TButton",  background="#1f6e30", foreground="#ffffff",
                    font=("Segoe UI", 9, "bold"), padding=(10, 5))
        s.map("Green.TButton", background=[("active", "#2ea043")])
        s.configure("Danger.TButton", background="#6e2020", foreground="#ffffff",
                    font=("Segoe UI", 9, "bold"), padding=(10, 5))
        s.map("Danger.TButton", background=[("active", C["red"])])
        # Entry
        s.configure("TEntry", fieldbackground=C["input"], foreground=C["text"],
                    insertcolor=C["text"], relief="flat", padding=(4, 4))
        s.map("TEntry", fieldbackground=[("focus", C["bg2"])],
              bordercolor=[("focus", C["accent"])])
        # Notebook
        s.configure("TNotebook", background=C["bg"], borderwidth=0, tabmargins=[0, 0, 0, 0])
        s.configure("TNotebook.Tab", background=C["bg2"], foreground=C["dim"],
                    font=("Segoe UI", 10), padding=[14, 7])
        s.map("TNotebook.Tab",
              background=[("selected", C["card"]), ("active", C["input"])],
              foreground=[("selected", C["accent"]), ("active", C["text"])])
        # Treeview
        s.configure("Treeview", background=C["card"], fieldbackground=C["card"],
                    foreground=C["text"], rowheight=26, font=("Segoe UI", 9))
        s.configure("Treeview.Heading", background=C["bg2"], foreground=C["dim"],
                    font=("Segoe UI", 9, "bold"), relief="flat")
        s.map("Treeview",
              background=[("selected", C["accent"])],
              foreground=[("selected", "#ffffff")])
        s.map("Treeview.Heading",
              background=[("active", C["input"])],
              foreground=[("active", C["accent"])])
        # Progressbar
        s.configure("TProgressbar", background=C["green"],
                    troughcolor=C["bg2"], borderwidth=0, thickness=8)
        # Scrollbar
        s.configure("TScrollbar", background=C["bg2"], troughcolor=C["bg"],
                    borderwidth=0, arrowsize=10)
        s.map("TScrollbar", background=[("active", C["border"])])
        # Checkbutton
        s.configure("TCheckbutton", background=C["bg"], foreground=C["text"],
                    font=("Segoe UI", 9))
        s.map("TCheckbutton", background=[("active", C["bg"])])

    # ── UI skeleton ───────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # ── Header bar ────────────────────────────────────────────────────────
        header_bar = tk.Frame(self, bg=C["bg2"],
                              highlightbackground=C["border"], highlightthickness=1)
        header_bar.pack(fill="x")

        left = tk.Frame(header_bar, bg=C["bg2"])
        left.pack(side="left", padx=16, pady=10)

        tk.Label(left, text="⚡ CyberSecurity Toolkit",
                 bg=C["bg2"], fg=C["text"],
                 font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(left, text="Defensive security workspace — All in One",
                 bg=C["bg2"], fg=C["dim"],
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))

        # Author badge ── right side
        badge = tk.Frame(header_bar, bg="#0d1f19",
                         highlightbackground="#3fb950", highlightthickness=1)
        badge.pack(side="right", padx=16, pady=10)
        tk.Label(badge, text="  🖥️  ", bg="#0d1f19", fg=C["green"],
                 font=("Segoe UI Emoji", 14)).pack(side="left")
        tk.Label(badge, text="© Sami Zi · The Creator", bg="#0d1f19", fg=C["green"],
                 font=("Segoe UI", 13, "bold")).pack(side="left")
        tk.Label(badge, text="  ", bg="#0d1f19").pack(side="left")

        # ── Status bar ────────────────────────────────────────────────────────
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Frame(self, bg=C["bg"],
                              highlightbackground=C["border"], highlightthickness=1)
        status_bar.pack(fill="x", side="bottom")
        tk.Label(status_bar, text="◉ ", bg=C["bg"], fg=C["green"],
                 font=("Segoe UI", 9)).pack(side="left", padx=(8, 0))
        ttk.Label(status_bar, textvariable=self.status_var, style="Dim.TLabel").pack(
            side="left", pady=3)
        tk.Label(status_bar, text="© Sami Zi · The Creator  |  Elite Cyber Defense", 
                 bg=C["bg"], fg=C["border"],
                 font=("Segoe UI", 8)).pack(side="right", padx=12)

        # ── Notebook ──────────────────────────────────────────────────────────
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=0, pady=0)

        self.dashboard_tab = ttk.Frame(nb)
        self.scanner_tab   = ttk.Frame(nb)
        self.monitor_tab   = ttk.Frame(nb)
        self.vault_tab     = ttk.Frame(nb)
        self.file_tab      = ttk.Frame(nb)

        nb.add(self.dashboard_tab, text="  Dashboard  ")
        nb.add(self.scanner_tab,   text="  Scanner  ")
        nb.add(self.monitor_tab,   text="  Connections  ")
        nb.add(self.vault_tab,     text="  Password Vault  ")
        nb.add(self.file_tab,      text="  File Encryptor  ")

        self._build_dashboard()
        self._build_scanner()
        self._build_monitor()
        self._build_vault()
        self._build_file_encryptor()

    # ── Dashboard ─────────────────────────────────────────────────────────────

    def _build_dashboard(self) -> None:
        frame = self.dashboard_tab
        frame.configure(style="TFrame")

        # Section title
        ttk.Label(frame, text="Overview", style="Header.TLabel").pack(
            anchor="w", padx=24, pady=(22, 4))
        ttk.Label(frame, text="Live metrics from your last scan / refresh",
                  style="Dim.TLabel").pack(anchor="w", padx=24, pady=(0, 16))

        # Metric cards
        cards_row = tk.Frame(frame, bg=C["bg"])
        cards_row.pack(fill="x", padx=24)

        self.metric_connections = tk.StringVar(value="—")
        self.metric_devices     = tk.StringVar(value="—")
        self.metric_vault       = tk.StringVar(value="—")

        card_defs = [
            ("Active Connections", self.metric_connections, "🔌", C["accent"]),
            ("Local Devices",      self.metric_devices,     "💻", C["green"]),
            ("Vault Entries",      self.metric_vault,        "🔐", C["purple"]),
        ]
        for col, (title, var, icon, color) in enumerate(card_defs):
            self._make_card(cards_row, title, var, icon, color, col)
            cards_row.columnconfigure(col, weight=1)

        # Divider
        tk.Frame(frame, bg=C["border"], height=1).pack(fill="x", padx=24, pady=20)

        # Refresh button + last-update label
        ctrl = tk.Frame(frame, bg=C["bg"])
        ctrl.pack(anchor="w", padx=24)

        self._dash_btn = ttk.Button(ctrl, text="⟳  Refresh Dashboard",
                                    command=self.refresh_dashboard, style="Accent.TButton")
        self._dash_btn.pack(side="left")
        _tip(self._dash_btn, "Refresh all metrics from current scan/vault data")

        self._dash_update_var = tk.StringVar(value="Not yet refreshed")
        ttk.Label(ctrl, textvariable=self._dash_update_var,
                  style="Dim.TLabel").pack(side="left", padx=16)

        # Info note
        tk.Frame(frame, bg=C["border"], height=1).pack(fill="x", padx=24, pady=20)
        ttk.Label(frame,
                  text="ℹ️  Run a scan or refresh connections first, then press Refresh Dashboard.",
                  style="Dim.TLabel").pack(anchor="w", padx=24)

    def _make_card(self, parent, title: str, var: tk.StringVar,
                   icon: str, color: str, col: int) -> None:
        card = tk.Frame(parent, bg=C["card"],
                        highlightbackground=C["border"], highlightthickness=1)
        card.grid(row=0, column=col, sticky="nsew", padx=6, ipady=10)

        tk.Label(card, text=icon, bg=C["card"], fg=color,
                 font=("Segoe UI Emoji", 26)).pack(pady=(18, 6))
        tk.Label(card, textvariable=var, bg=C["card"], fg=C["text"],
                 font=("Segoe UI", 32, "bold")).pack()
        tk.Label(card, text=title, bg=C["card"], fg=C["dim"],
                 font=("Segoe UI", 10)).pack(pady=(4, 18))

    # ── Scanner ───────────────────────────────────────────────────────────────

    def _build_scanner(self) -> None:
        frame = self.scanner_tab
        frame.rowconfigure(3, weight=1)
        frame.columnconfigure(0, weight=1)

        # Title
        ttk.Label(frame, text="Local Network Scanner", style="Header.TLabel").grid(
            row=0, column=0, sticky="w", padx=20, pady=(18, 4))

        # Controls row
        ctrl = tk.Frame(frame, bg=C["bg"])
        ctrl.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 10))

        self._scan_btn = ttk.Button(ctrl, text="🔍  Scan Network",
                                    command=self.scan_devices, style="Green.TButton")
        self._scan_btn.pack(side="left", padx=(0, 8))
        _tip(self._scan_btn, "Scan local /24 subnet for active devices")

        self._export_scan_btn = ttk.Button(ctrl, text="📤  Export CSV",
                                           command=self.export_scan_csv)
        self._export_scan_btn.pack(side="left", padx=(0, 16))
        _tip(self._export_scan_btn, "Export current results to a CSV file")

        ttk.Label(ctrl, text="Filter:", style="Dim.TLabel").pack(side="left", padx=(0, 4))
        self._scan_filter_var = tk.StringVar()
        filter_entry = ttk.Entry(ctrl, textvariable=self._scan_filter_var, width=28)
        filter_entry.pack(side="left")
        _tip(filter_entry, "Filter results by any column")
        self._scan_filter_var.trace_add("write", lambda *_: self._apply_scan_filter())

        # Progress bar + status
        prog_frame = tk.Frame(frame, bg=C["bg"])
        prog_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 4))

        self._scan_prog_var = tk.DoubleVar(value=0)
        self._scan_prog_bar = ttk.Progressbar(
            prog_frame, variable=self._scan_prog_var, maximum=100, mode="determinate",
            length=400)
        self._scan_prog_bar.pack(side="left")

        self._scan_status_var = tk.StringVar(value="")
        self._scan_status_lbl = ttk.Label(prog_frame, textvariable=self._scan_status_var,
                                          style="Dim.TLabel")
        self._scan_status_lbl.pack(side="left", padx=10)

        # Results table
        tree_frame = tk.Frame(frame, bg=C["bg"])
        tree_frame.grid(row=3, column=0, sticky="nsew", padx=20, pady=(0, 12))
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        cols = ("ip", "mac", "hostname", "vendor", "ports")
        self.device_tree = ttk.Treeview(tree_frame, columns=cols,
                                        show="headings", height=18)
        widths = {"ip": 130, "mac": 160, "hostname": 200, "vendor": 160, "ports": 200}
        for col in cols:
            self.device_tree.heading(col, text=col.upper(),
                                     command=lambda c=col: self._sort_tree(
                                         self.device_tree, c, cols))
            self.device_tree.column(col, width=widths[col], minwidth=80)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=vsb.set)
        self.device_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

    # ── Connections ───────────────────────────────────────────────────────────

    def _build_monitor(self) -> None:
        frame = self.monitor_tab
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        ttk.Label(frame, text="Active Connections", style="Header.TLabel").grid(
            row=0, column=0, sticky="w", padx=20, pady=(18, 0))

        ctrl = tk.Frame(frame, bg=C["bg"])
        ctrl.grid(row=0, column=1, sticky="e", padx=20, pady=(18, 0))
        btn = ttk.Button(ctrl, text="⟳  Refresh", command=self.refresh_connections,
                         style="Accent.TButton")
        btn.pack()
        _tip(btn, "Refresh the list of active network connections")

        cols = ("pid", "process", "local", "remote", "status", "risk")
        tree_frame = tk.Frame(frame, bg=C["bg"])
        tree_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=20, pady=10)
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self.conn_tree = ttk.Treeview(tree_frame, columns=cols,
                                      show="headings", height=22)
        for col in cols:
            self.conn_tree.heading(col, text=col.upper())
            self.conn_tree.column(col, width=170)
        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            command=self.conn_tree.yview)
        self.conn_tree.configure(yscrollcommand=vsb.set)
        self.conn_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        # Red tag for high-risk rows
        self.conn_tree.tag_configure("high", foreground=C["red"])

    # ── Password Vault ────────────────────────────────────────────────────────

    def _build_vault(self) -> None:
        frame = self.vault_tab
        frame.rowconfigure(3, weight=1)
        frame.columnconfigure(0, weight=1)

        ttk.Label(frame, text="Password Vault", style="Header.TLabel").grid(
            row=0, column=0, sticky="w", padx=20, pady=(18, 4))

        # Form  (row 1)
        form = tk.Frame(frame, bg=C["card"],
                        highlightbackground=C["border"], highlightthickness=1)
        form.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 6))
        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=1)

        self.vault_master_var = tk.StringVar()
        self.service_var      = tk.StringVar()
        self.username_var     = tk.StringVar()
        self.password_var     = tk.StringVar()

        fields = [
            ("Master password:", "vault_master_var", True,  0, 0),
            ("Service:",         "service_var",       False, 1, 0),
            ("Username:",        "username_var",       False, 0, 2),
            ("Password:",        "password_var",       False, 1, 2),
        ]
        for label, attr, secret, frow, col_off in fields:
            tk.Label(form, text=label, bg=C["card"], fg=C["dim"],
                     font=("Segoe UI", 9)).grid(
                row=frow, column=col_off, sticky="w", padx=(12, 4), pady=8)
            entry = ttk.Entry(form, textvariable=getattr(self, attr),
                              show="*" if secret else "")
            entry.grid(row=frow, column=col_off + 1, sticky="ew", padx=(0, 12), pady=8)

        # Action buttons  (row 2)
        btns = tk.Frame(frame, bg=C["bg"])
        btns.grid(row=2, column=0, sticky="w", padx=20, pady=(0, 8))

        btn_defs = [
            ("🔑  Init Vault",   self.init_vault,          "TButton"),
            ("✨  Generate",     self.generate_password,   "TButton"),
            ("💾  Save Entry",   self.save_entry,          "Green.TButton"),
            ("🔄  Load",         self.load_entries,        "TButton"),
            ("🗑️  Delete",       self.delete_vault_entry,  "Danger.TButton"),
            ("📤  Export",       self.export_vault,        "TButton"),
            ("📥  Import File",  self.import_vault_file,   "TButton"),
        ]
        tips = [
            "Initialise a new vault with the master password",
            "Generate a cryptographically secure random password",
            "Save the current entry to the vault",
            "Load all entries (requires master password)",
            "Delete the selected entry",
            "Export all entries to TXT / CSV / JSON",
            "Import entries from a JSON or CSV file",
        ]
        for (txt, cmd, sty), tip in zip(btn_defs, tips):
            b = ttk.Button(btns, text=txt, command=cmd, style=sty)
            b.pack(side="left", padx=3)
            _tip(b, tip)

        # Table  (row 3)
        tree_frame = tk.Frame(frame, bg=C["bg"])
        tree_frame.grid(row=3, column=0, sticky="nsew", padx=20, pady=(0, 12))
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        cols = ("service", "username", "password", "created_at")
        self.vault_tree = ttk.Treeview(tree_frame, columns=cols,
                                       show="headings", height=14)
        col_widths = {"service": 200, "username": 200, "password": 220, "created_at": 200}
        for col in cols:
            self.vault_tree.heading(col, text=col.upper())
            self.vault_tree.column(col, width=col_widths[col])
        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            command=self.vault_tree.yview)
        self.vault_tree.configure(yscrollcommand=vsb.set)
        self.vault_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

    # ── File Encryptor ────────────────────────────────────────────────────────

    def _build_file_encryptor(self) -> None:
        frame = self.file_tab
        frame.columnconfigure(0, weight=1)

        ttk.Label(frame, text="File Encryptor", style="Header.TLabel").pack(
            anchor="w", padx=22, pady=(20, 2))
        ttk.Label(frame,
                  text="AES-256-GCM  ·  PBKDF2-HMAC-SHA256  (600 000 iterations)  ·  Random 16-byte salt + 12-byte IV",
                  style="Dim.TLabel").pack(anchor="w", padx=22, pady=(0, 14))

        # Drop zone
        self.file_path_var = tk.StringVar()
        dz_outer = tk.Frame(frame, bg=C["bg"])
        dz_outer.pack(fill="x", padx=22, pady=(0, 8))

        self._drop_zone = tk.Frame(dz_outer, bg=C["card"], height=90, cursor="hand2",
                                   highlightbackground=C["border"], highlightthickness=2)
        self._drop_zone.pack(fill="x")
        self._drop_zone.pack_propagate(False)

        self._drop_lbl = tk.Label(self._drop_zone,
                                  text="📁   Drop a file here  —  or click to browse",
                                  bg=C["card"], fg=C["dim"],
                                  font=("Segoe UI", 12))
        self._drop_lbl.place(relx=0.5, rely=0.5, anchor="center")

        for w in (self._drop_zone, self._drop_lbl):
            w.bind("<Button-1>", lambda _e: self.select_file())
            w.bind("<Enter>",
                   lambda _e: self._drop_zone.configure(highlightbackground=C["accent"]))
            w.bind("<Leave>",
                   lambda _e: self._drop_zone.configure(highlightbackground=C["border"]))

        if _HAS_DND:
            self._drop_zone.drop_target_register(DND_FILES)
            self._drop_zone.dnd_bind("<<Drop>>", self._on_file_drop)

        # File path row (also editable)
        row_file = tk.Frame(frame, bg=C["bg"])
        row_file.pack(fill="x", padx=22, pady=(0, 6))
        tk.Label(row_file, text="File:", bg=C["bg"], fg=C["dim"],
                 font=("Segoe UI", 9), width=9, anchor="w").pack(side="left")
        file_entry = ttk.Entry(row_file, textvariable=self.file_path_var)
        file_entry.pack(side="left", fill="x", expand=True, padx=(4, 8))
        browse_btn = ttk.Button(row_file, text="Browse…", command=self.select_file)
        browse_btn.pack(side="left")
        _tip(file_entry, "Path to the file you want to encrypt or decrypt")

        # Password row
        row_pw = tk.Frame(frame, bg=C["bg"])
        row_pw.pack(fill="x", padx=22, pady=(0, 12))
        tk.Label(row_pw, text="Password:", bg=C["bg"], fg=C["dim"],
                 font=("Segoe UI", 9), width=9, anchor="w").pack(side="left")
        self.file_key_var = tk.StringVar()
        self._enc_pw_entry = ttk.Entry(row_pw, textvariable=self.file_key_var, show="*")
        self._enc_pw_entry.pack(side="left", fill="x", expand=True, padx=(4, 8))
        _tip(self._enc_pw_entry, "Encryption / decryption password")
        self._enc_show_var = tk.BooleanVar(value=False)
        show_chk = ttk.Checkbutton(row_pw, text="Show password",
                                   variable=self._enc_show_var,
                                   command=self._toggle_enc_pw)
        show_chk.pack(side="left")

        # Action buttons
        row_btns = tk.Frame(frame, bg=C["bg"])
        row_btns.pack(anchor="w", padx=22, pady=(0, 12))
        self._btn_encrypt = ttk.Button(row_btns, text="🔐  Encrypt File",
                                       command=self.encrypt_file, style="Green.TButton")
        self._btn_encrypt.pack(side="left", padx=(0, 10))
        _tip(self._btn_encrypt, "Encrypt the selected file with AES-256-GCM")

        self._btn_decrypt = ttk.Button(row_btns, text="🔓  Decrypt File",
                                       command=self.decrypt_file)
        self._btn_decrypt.pack(side="left")
        _tip(self._btn_decrypt, "Decrypt a .cstk file — supports V4, V3, V2, V1 formats")

        # Progress / status
        self._enc_status_var = tk.StringVar(value="")
        self._enc_status_lbl = ttk.Label(frame, textvariable=self._enc_status_var,
                                         style="Dim.TLabel")
        self._enc_status_lbl.pack(anchor="w", padx=22, pady=(0, 4))

    # ── helpers ───────────────────────────────────────────────────────────────

    def _set_status(self, msg: str) -> None:
        self.status_var.set(msg)

    @staticmethod
    def _clear_tree(tree: ttk.Treeview) -> None:
        tree.delete(*tree.get_children())

    def _sort_tree(self, tree: ttk.Treeview, col: str, all_cols: tuple) -> None:
        reverse = self._sort_state.get(col, False)
        data = [(tree.set(item, col), item) for item in tree.get_children("")]
        try:
            data.sort(key=lambda x: float(x[0].replace(",", "")), reverse=reverse)
        except ValueError:
            data.sort(key=lambda x: x[0].lower(), reverse=reverse)
        for idx, (_, item) in enumerate(data):
            tree.move(item, "", idx)
        self._sort_state[col] = not reverse
        arrow = " ▲" if not reverse else " ▼"
        for c in all_cols:
            tree.heading(c, text=c.upper() + (arrow if c == col else ""))

    # ── Dashboard actions ─────────────────────────────────────────────────────

    def refresh_dashboard(self) -> None:
        self.metric_connections.set(str(len(self.conn_tree.get_children())))
        self.metric_devices.set(str(len(self.device_tree.get_children())))
        self.metric_vault.set(str(len(self.vault_tree.get_children())))
        ts = datetime.now().strftime("%H:%M:%S")
        self._dash_update_var.set(f"Last updated: {ts}")
        self._dash_btn.configure(text="✓  Updated!")
        self.after(1600, lambda: self._dash_btn.configure(text="⟳  Refresh Dashboard"))
        self._set_status(f"Dashboard refreshed at {ts}")

    # ── Scanner actions ───────────────────────────────────────────────────────

    def scan_devices(self) -> None:
        self._scan_rows = []
        self._clear_tree(self.device_tree)
        self._scan_prog_var.set(0)
        self._scan_status_var.set("Starting scan…")
        self._scan_btn.configure(state="disabled")

        def on_progress(msg: str, pct: int) -> None:
            self.after(0, self._scan_status_var.set, msg)
            self.after(0, self._scan_prog_var.set, pct)

        def task() -> None:
            try:
                rows = self.scanner.scan_local_devices(progress_callback=on_progress)
                self.after(0, self._render_devices, rows)
            except Exception as exc:
                self.after(0, self._scan_status_var.set, f"❌  {exc}")
                self.after(0, self._set_status, f"Scan failed: {exc}")
            finally:
                self.after(0, lambda: self._scan_btn.configure(state="normal"))

        threading.Thread(target=task, daemon=True).start()

    def _render_devices(self, rows: list) -> None:
        self._scan_rows = rows
        self._apply_scan_filter()
        self._set_status(f"Scan complete — {len(rows)} device(s) found")
        self.refresh_dashboard()

    def _apply_scan_filter(self) -> None:
        query = self._scan_filter_var.get().lower()
        self._clear_tree(self.device_tree)
        for row in self._scan_rows:
            vals = (row["ip"], row["mac"], row["hostname"], row["vendor"], row["ports"])
            if not query or any(query in v.lower() for v in vals):
                self.device_tree.insert("", "end", values=vals)

    def export_scan_csv(self) -> None:
        if not self._scan_rows:
            messagebox.showinfo("Scanner", "No scan results to export. Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            title="Export scan results",
            defaultextension=".csv",
            filetypes=[("CSV file", "*.csv"), ("All files", "*.*")],
            initialfile="scan_results.csv",
        )
        if not path:
            return
        try:
            target = self.scanner.export_csv(self._scan_rows, path)
            messagebox.showinfo("Scanner", f"Exported {len(self._scan_rows)} rows to:\n{target}")
            self._set_status(f"Scan exported → {target.name}")
        except Exception as exc:
            messagebox.showerror("Scanner", f"Export failed:\n{exc}")

    # ── Connections actions ───────────────────────────────────────────────────

    def refresh_connections(self) -> None:
        self._clear_tree(self.conn_tree)
        rows = self.monitor.list_connections()
        for row in rows:
            tag = ("high",) if row["risk"] == "High" else ()
            self.conn_tree.insert("", "end",
                values=(row["pid"], row["process"], row["local"],
                        row["remote"], row["status"], row["risk"]),
                tags=tag)
        self._set_status(f"Connections refreshed — {len(rows)} rows")
        self.refresh_dashboard()

    # ── Vault actions ─────────────────────────────────────────────────────────

    def init_vault(self) -> None:
        master = self.vault_master_var.get().strip()
        if not master:
            messagebox.showerror("Vault", "Please enter a master password.")
            return
        try:
            self.vault.initialize(master)
            messagebox.showinfo("Vault", f"Vault created at:\n{VAULT_FILE}")
            self._set_status("Vault initialised")
        except FileExistsError:
            messagebox.showwarning("Vault", "Vault already exists.")

    def generate_password(self) -> None:
        self.password_var.set(self.vault.generate_password())
        self._set_status("Secure password generated")

    def save_entry(self) -> None:
        master = self.vault_master_var.get().strip()
        svc    = self.service_var.get().strip()
        usr    = self.username_var.get().strip()
        pwd    = self.password_var.get().strip()
        if not all([master, svc, usr, pwd]):
            messagebox.showerror("Vault", "Master password, service, username and password are all required.")
            return
        try:
            if not self.vault.exists():
                self.vault.initialize(master)
            self.vault.add_entry(master, svc, usr, pwd)
            self._set_status(f"Entry '{svc}' saved")
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
            self.vault_tree.insert("", "end",
                values=(row["service"], row["username"], row["password"], row["created_at"]))
        self._set_status(f"Loaded {len(rows)} vault entries")
        self.refresh_dashboard()

    def delete_vault_entry(self) -> None:
        sel = self.vault_tree.selection()
        if not sel:
            messagebox.showwarning("Vault", "Select an entry in the table first.")
            return
        master = self.vault_master_var.get().strip()
        if not master:
            messagebox.showerror("Vault", "Enter master password first.")
            return
        svc, usr, _pwd, created = self.vault_tree.item(sel[0], "values")
        if not messagebox.askyesno("Vault",
                                   f"Delete entry for '{svc}' ({usr})?\n\nThis cannot be undone."):
            return
        try:
            ok = self.vault.delete_entry(master, svc, usr, created)
            if ok:
                self._set_status(f"Entry '{svc}' deleted")
                self.load_entries()
            else:
                messagebox.showerror("Vault", "Entry not found — reload first.")
        except ValueError as exc:
            messagebox.showerror("Vault", str(exc))

    def export_vault(self) -> None:
        master = self.vault_master_var.get().strip()
        if not master:
            messagebox.showerror("Vault", "Enter master password first.")
            return
        try:
            rows = self.vault.list_entries(master)
        except (FileNotFoundError, ValueError) as exc:
            messagebox.showerror("Vault", str(exc))
            return
        if not rows:
            messagebox.showinfo("Vault", "No entries to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Export vault",
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("CSV", "*.csv"), ("JSON", "*.json"), ("All", "*.*")],
            initialfile="passwords_export.txt",
        )
        if not path:
            return
        if not messagebox.askyesno("Vault Export",
                                   "This writes readable passwords to a local file.\n"
                                   "Protect the file carefully.\n\nContinue?"):
            return
        try:
            target = self.vault.export_entries(master, path)
            messagebox.showinfo("Vault", f"Exported {len(rows)} entries to:\n{target}")
            self._set_status(f"Vault exported → {target.name}")
        except (OSError, ValueError) as exc:
            messagebox.showerror("Vault", f"Export failed:\n{exc}")

    def import_vault_file(self) -> None:
        master = self.vault_master_var.get().strip()
        if not master:
            messagebox.showerror("Vault", "Enter master password first.")
            return
        path = filedialog.askopenfilename(
            title="Import vault entries",
            filetypes=[("JSON / CSV", "*.json *.csv"), ("JSON", "*.json"),
                       ("CSV", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            count = self.vault.import_file(master, path)
            messagebox.showinfo("Vault", f"Successfully imported {count} entry/entries.")
            self._set_status(f"Imported {count} entries from file")
            self.load_entries()
        except (FileNotFoundError, ValueError) as exc:
            messagebox.showerror("Vault", f"Import failed:\n{exc}")

    # ── File Encryptor actions ────────────────────────────────────────────────

    def select_file(self) -> None:
        path = filedialog.askopenfilename(title="Select file to encrypt / decrypt")
        if path:
            self.file_path_var.set(path)
            self._drop_lbl.configure(text=f"📄  {Path(path).name}", fg=C["accent"])

    def _on_file_drop(self, event) -> None:
        path = event.data.strip()
        if path.startswith("{") and path.endswith("}"):
            path = path[1:-1]
        self.file_path_var.set(path)
        self._drop_lbl.configure(text=f"📄  {Path(path).name}", fg=C["accent"])

    def _toggle_enc_pw(self) -> None:
        self._enc_pw_entry.configure(show="" if self._enc_show_var.get() else "*")

    def _set_enc_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        self._btn_encrypt.configure(state=state)
        self._btn_decrypt.configure(state=state)

    def _set_enc_status(self, msg: str, color: str = C["dim"]) -> None:
        self._enc_status_var.set(msg)
        self._enc_status_lbl.configure(foreground=color)

    def encrypt_file(self) -> None:
        path = self.file_path_var.get().strip()
        key  = self.file_key_var.get().strip()
        if not path or not key:
            messagebox.showerror("Encryptor", "Choose a file and enter a password.")
            return

        def task() -> None:
            self.after(0, self._set_enc_busy, True)
            self.after(0, self._set_enc_status,
                       "⏳  Deriving key (PBKDF2-HMAC-SHA256 · 600 000 iter)…", C["yellow"])
            self.after(0, self._set_status, "Encrypting file…")
            try:
                target = self.file_cipher.encrypt_file(path, key)
                self.after(0, self._set_enc_status,
                           f"✅  Encrypted  →  {target.name}", C["green"])
                self.after(0, self._set_status, "File encrypted successfully")
                self.after(0, messagebox.showinfo, "Encryptor",
                           f"File encrypted successfully!\n\n"
                           f"Output: {target}\n\n"
                           f"Algorithm : AES-256-GCM\n"
                           f"KDF       : PBKDF2-HMAC-SHA256  (600 000 iterations)\n"
                           f"Format    : V4 binary (.cstk)")
            except Exception as exc:
                self.after(0, self._set_enc_status, f"❌  {exc}", C["red"])
                self.after(0, self._set_status, "Encryption failed")
                self.after(0, messagebox.showerror, "Encryptor", str(exc))
            finally:
                self.after(0, self._set_enc_busy, False)

        threading.Thread(target=task, daemon=True).start()

    def decrypt_file(self) -> None:
        path = self.file_path_var.get().strip()
        key  = self.file_key_var.get().strip()
        if not path or not key:
            messagebox.showerror("Encryptor", "Choose an encrypted file and enter the password.")
            return

        def task() -> None:
            self.after(0, self._set_enc_busy, True)
            self.after(0, self._set_enc_status, "⏳  Deriving key…", C["yellow"])
            self.after(0, self._set_status, "Decrypting file…")
            try:
                target = self.file_cipher.decrypt_file(path, key)
                self.after(0, self._set_enc_status,
                           f"✅  Decrypted  →  {target.name}", C["green"])
                self.after(0, self._set_status, "File decrypted successfully")
                self.after(0, messagebox.showinfo, "Encryptor",
                           f"File decrypted successfully!\n\nOutput: {target}")
            except Exception as exc:
                self.after(0, self._set_enc_status, f"❌  {exc}", C["red"])
                self.after(0, self._set_status, "Decryption failed")
                self.after(0, messagebox.showerror, "Encryptor", str(exc))
            finally:
                self.after(0, self._set_enc_busy, False)

        threading.Thread(target=task, daemon=True).start()


# ── Entry point ───────────────────────────────────────────────────────────────

def run_app() -> None:
    app = ToolkitApp()
    app.mainloop()

