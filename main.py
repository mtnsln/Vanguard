from __future__ import annotations

import json
import os
import queue
import shutil
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from datetime import datetime

from vanguard.scanner import Scanner, ScanResult
from vanguard.quarantine import QuarantineManager
from vanguard.logger import get_logger

APP_NAME = "Vanguard Antivirus"
ROOT = Path(__file__).resolve().parent
SIGNATURES_FILE = ROOT / "signatures.json"
QUARANTINE_DIR = ROOT / "quarantine"
LOG_DIR = ROOT / "logs"

class VanguardApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1050x680")
        self.minsize(850, 560)
        self.configure(bg="#101827")

        self.logger = get_logger(LOG_DIR)
        self.scanner = Scanner(SIGNATURES_FILE, logger=self.logger)
        self.quarantine = QuarantineManager(QUARANTINE_DIR, logger=self.logger)
        self.events = queue.Queue()
        self.scan_thread = None
        self.results: list[ScanResult] = []
        self._build_ui()
        self.after(100, self._process_events)
        self._refresh_quarantine_count()

    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=25, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("TButton", padding=7)
        style.configure("TProgressbar", thickness=12)

        header = tk.Frame(self, bg="#101827", padx=22, pady=18)
        header.pack(fill="x")
        tk.Label(header, text="VANGUARD", font=("Segoe UI", 24, "bold"),
                 fg="#f3f6fb", bg="#101827").pack(anchor="w")
        tk.Label(header, text="ANTIVIRUS  •  LOCAL FILE SCANNER",
                 font=("Segoe UI", 10), fg="#8da3bf", bg="#101827").pack(anchor="w", pady=(2, 0))

        toolbar = tk.Frame(self, bg="#172337", padx=16, pady=12)
        toolbar.pack(fill="x", padx=18)
        self.scan_file_btn = ttk.Button(toolbar, text="Scan file", command=self.scan_file)
        self.scan_file_btn.pack(side="left", padx=(0, 8))
        self.scan_folder_btn = ttk.Button(toolbar, text="Scan folder", command=self.scan_folder)
        self.scan_folder_btn.pack(side="left", padx=(0, 8))
        self.quarantine_btn = ttk.Button(toolbar, text="Quarantine selected", command=self.quarantine_selected)
        self.quarantine_btn.pack(side="left", padx=(0, 8))
        self.restore_btn = ttk.Button(toolbar, text="Manage quarantine", command=self.manage_quarantine)
        self.restore_btn.pack(side="left")
        self.status_var = tk.StringVar(value="Ready — choose a file or folder to scan.")
        tk.Label(toolbar, textvariable=self.status_var, bg="#172337", fg="#c6d2e1",
                 font=("Segoe UI", 9)).pack(side="right", padx=(10, 0))

        content = tk.Frame(self, bg="#101827", padx=18, pady=14)
        content.pack(fill="both", expand=True)
        columns = ("status", "path", "reason", "sha256")
        self.tree = ttk.Treeview(content, columns=columns, show="headings", selectmode="extended")
        self.tree.heading("status", text="RESULT")
        self.tree.heading("path", text="FILE")
        self.tree.heading("reason", text="DETECTION REASON")
        self.tree.heading("sha256", text="SHA-256")
        self.tree.column("status", width=105, anchor="center", stretch=False)
        self.tree.column("path", width=330)
        self.tree.column("reason", width=230)
        self.tree.column("sha256", width=260)
        yscroll = ttk.Scrollbar(content, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(content, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        content.rowconfigure(0, weight=1)
        content.columnconfigure(0, weight=1)
        self.tree.tag_configure("threat", foreground="#b42318")
        self.tree.tag_configure("clean", foreground="#16794b")
        self.tree.tag_configure("error", foreground="#9a6700")

        footer = tk.Frame(self, bg="#172337", padx=18, pady=12)
        footer.pack(fill="x", padx=18, pady=(0, 18))
        self.progress = ttk.Progressbar(footer, mode="indeterminate", length=220)
        self.progress.pack(side="left")
        self.summary_var = tk.StringVar(value="No scan has been run yet.")
        tk.Label(footer, textvariable=self.summary_var, bg="#172337", fg="#d7e1ee",
                 font=("Segoe UI", 9)).pack(side="left", padx=14)
        tk.Label(footer, text="Prototype: not a replacement for Microsoft Defender",
                 bg="#172337", fg="#8da3bf", font=("Segoe UI", 8)).pack(side="right")

    def _set_scanning(self, scanning: bool):
        state = "disabled" if scanning else "normal"
        self.scan_file_btn.configure(state=state)
        self.scan_folder_btn.configure(state=state)
        self.progress.start(10) if scanning else self.progress.stop()

    def scan_file(self):
        path = filedialog.askopenfilename(title="Select a file to scan")
        if path:
            self._start_scan(Path(path))

    def scan_folder(self):
        path = filedialog.askdirectory(title="Select a folder to scan")
        if path:
            self._start_scan(Path(path))

    def _start_scan(self, path: Path):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        self.results = []
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._set_scanning(True)
        self.status_var.set(f"Scanning: {path}")
        self.summary_var.set("Scanning files…")
        self.scan_thread = threading.Thread(target=self._scan_worker, args=(path,), daemon=True)
        self.scan_thread.start()

    def _scan_worker(self, path: Path):
        try:
            for result in self.scanner.scan_path(path, excluded_dirs={QUARANTINE_DIR, LOG_DIR}):
                self.events.put(("result", result))
            self.events.put(("finished", path))
        except Exception as exc:
            self.logger.exception("Scan failed")
            self.events.put(("fatal", str(exc)))

    def _process_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "result":
                    result = event[1]
                    self.results.append(result)
                    status = result.status.upper()
                    tag = "threat" if result.is_threat else ("error" if result.status == "ERROR" else "clean")
                    self.tree.insert("", "end", iid=str(len(self.results)-1),
                                     values=(status, str(result.path), result.reason, result.sha256 or ""),
                                     tags=(tag,))
                elif kind == "finished":
                    self._set_scanning(False)
                    threats = sum(r.is_threat for r in self.results)
                    errors = sum(r.status == "ERROR" for r in self.results)
                    clean = sum(r.status == "CLEAN" for r in self.results)
                    self.status_var.set("Scan complete")
                    self.summary_var.set(f"{len(self.results)} item(s) • {threats} detection(s) • {clean} clean • {errors} error(s)")
                    self.logger.info("Scan complete: %s items, %s detections", len(self.results), threats)
                elif kind == "fatal":
                    self._set_scanning(False)
                    messagebox.showerror("Scan error", event[1])
        except queue.Empty:
            pass
        self.after(100, self._process_events)

    def quarantine_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Select a detection", "Select one or more scan results first.")
            return
        targets = []
        for iid in selected:
            try:
                result = self.results[int(iid)]
                if result.is_threat:
                    targets.append(result)
            except (ValueError, IndexError):
                continue
        if not targets:
            messagebox.showinfo("No detections selected", "Only items marked DETECTED can be quarantined.")
            return
        if not messagebox.askyesno("Confirm quarantine",
            f"Move {len(targets)} detected file(s) into Vanguard's quarantine?\n\n"
            "This moves the files; it does not delete them. Only quarantine files you trust this scanner to have identified correctly."):
            return
        moved = 0
        for result in targets:
            try:
                self.quarantine.quarantine(result.path, reason=result.reason, sha256=result.sha256)
                moved += 1
            except Exception as exc:
                self.logger.exception("Could not quarantine %s", result.path)
                messagebox.showwarning("Quarantine issue", f"Could not quarantine:\n{result.path}\n\n{exc}")
        messagebox.showinfo("Quarantine", f"Moved {moved} file(s) to quarantine.")
        self._refresh_quarantine_count()

    def _refresh_quarantine_count(self):
        count = len(self.quarantine.list_items())
        self.status_var.set(f"Quarantine: {count} item(s)")

    def manage_quarantine(self):
        items = self.quarantine.list_items()
        win = tk.Toplevel(self)
        win.title("Vanguard — Quarantine")
        win.geometry("850x400")
        win.transient(self)
        frame = ttk.Frame(win, padding=12)
        frame.pack(fill="both", expand=True)
        cols = ("id", "original", "reason", "date")
        tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse")
        for c, title in zip(cols, ("ID", "ORIGINAL PATH", "REASON", "QUARANTINED AT")):
            tree.heading(c, text=title)
        tree.column("id", width=170)
        tree.column("original", width=300)
        tree.column("reason", width=180)
        tree.column("date", width=150)
        tree.pack(fill="both", expand=True)
        by_id = {}
        for item in items:
            by_id[item["id"]] = item
            tree.insert("", "end", iid=item["id"], values=(item["id"], item["original_path"], item["reason"], item["quarantined_at"]))
        buttons = ttk.Frame(win, padding=(12, 0, 12, 12))
        buttons.pack(fill="x")
        def restore():
            selection = tree.selection()
            if not selection:
                messagebox.showinfo("Select an item", "Choose a quarantined item to restore.", parent=win)
                return
            item = by_id[selection[0]]
            if not messagebox.askyesno("Restore file",
                "Restoring a detected file can reintroduce a threat.\nRestore only if you are sure it is safe.",
                parent=win):
                return
            try:
                destination = filedialog.asksaveasfilename(
                    parent=win, title="Choose restore location",
                    initialfile=Path(item["original_path"]).name,
                    initialdir=str(Path(item["original_path"]).parent if Path(item["original_path"]).parent.exists() else Path.home()))
                if not destination:
                    return
                self.quarantine.restore(item["id"], Path(destination))
                messagebox.showinfo("Restored", f"Restored to:\n{destination}", parent=win)
                win.destroy()
                self._refresh_quarantine_count()
            except Exception as exc:
                messagebox.showerror("Restore failed", str(exc), parent=win)
        ttk.Button(buttons, text="Restore selected…", command=restore).pack(side="left")
        ttk.Button(buttons, text="Refresh", command=lambda: (win.destroy(), self.manage_quarantine())).pack(side="left", padx=8)
        ttk.Button(buttons, text="Close", command=win.destroy).pack(side="right")

if __name__ == "__main__":
    app = VanguardApp()
    app.mainloop()
