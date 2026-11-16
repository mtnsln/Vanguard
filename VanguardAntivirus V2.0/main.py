from __future__ import annotations

import csv
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from datetime import datetime

from vanguard import __version__
from vanguard.scanner import Scanner, ScanResult
from vanguard.quarantine import QuarantineManager
from vanguard.logger import get_logger

APP_NAME = "VANGUARD"
ROOT = Path(__file__).resolve().parent
DATA_DIR = Path.home() / ".vanguard"
SIGNATURES_FILE = ROOT / "signatures.json"
QUARANTINE_DIR = DATA_DIR / "quarantine"
LOG_DIR = DATA_DIR / "logs"

BG = "#111512"
PANEL = "#191f1b"
PANEL_2 = "#202822"
LINE = "#303a32"
TEXT = "#edf2ed"
MUTED = "#9aa69b"
GREEN = "#9acb70"
RED = "#e17b72"
AMBER = "#d8b66a"


class VanguardApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} — Local Security")
        self.geometry("1180x760")
        self.minsize(960, 650)
        self.configure(bg=BG)
        self.logger = get_logger(LOG_DIR)
        self.scanner = Scanner(SIGNATURES_FILE, self.logger)
        self.quarantine = QuarantineManager(QUARANTINE_DIR, self.logger)
        self.events = queue.Queue()
        self.cancel_event = threading.Event()
        self.scan_thread = None
        self.results: list[ScanResult] = []
        self.scan_started = None
        self._style()
        self._build_ui()
        self.after(100, self._process_events)
        self._refresh_stats()

    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background=PANEL, foreground=TEXT, fieldbackground=PANEL,
                        rowheight=31, borderwidth=0, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=PANEL_2, foreground=MUTED,
                        relief="flat", font=("Segoe UI", 8, "bold"))
        style.map("Treeview", background=[("selected", "#344536")], foreground=[("selected", TEXT)])
        style.configure("TProgressbar", troughcolor=PANEL_2, background=GREEN, borderwidth=0, thickness=7)

    def _label(self, parent, text, size=10, color=TEXT, weight="normal", **kwargs):
        return tk.Label(parent, text=text, bg=kwargs.pop("bg", PANEL), fg=color,
                        font=("Segoe UI", size, weight), **kwargs)

    def _button(self, parent, text, command, primary=False):
        bg = GREEN if primary else PANEL_2
        fg = "#152015" if primary else TEXT
        return tk.Button(parent, text=text, command=command, bg=bg, fg=fg,
                         activebackground=GREEN if primary else LINE, activeforeground=TEXT if not primary else "#152015",
                         relief="flat", bd=0, padx=15, pady=9, cursor="hand2",
                         font=("Segoe UI", 9, "bold" if primary else "normal"))

    def _build_ui(self):
        header = tk.Frame(self, bg=BG, padx=28, pady=22)
        header.pack(fill="x")
        brand = tk.Frame(header, bg=BG)
        brand.pack(side="left")
        self._label(brand, "VANGUARD", 20, TEXT, "bold", bg=BG).pack(anchor="w")
        self._label(brand, "LOCAL FILE SECURITY  /  VERSION " + __version__, 8, MUTED, bg=BG).pack(anchor="w", pady=(3, 0))
        self._label(header, "DESKTOP SCANNER", 8, MUTED, bg=BG).pack(side="right", anchor="center")

        body = tk.Frame(self, bg=BG, padx=28)
        body.pack(fill="both", expand=True)
        top = tk.Frame(body, bg=BG)
        top.pack(fill="x", pady=(0, 18))
        self._label(top, "Overview", 17, TEXT, "bold", bg=BG).pack(side="left")
        self.status_pill = self._label(top, "●  READY", 8, GREEN, "bold", bg=BG)
        self.status_pill.pack(side="right", pady=5)

        cards = tk.Frame(body, bg=BG)
        cards.pack(fill="x", pady=(0, 18))
        self.stat_vars = {}
        for key, title, value, color in [
            ("scanned", "FILES SCANNED", "0", TEXT),
            ("detected", "DETECTIONS", "0", RED),
            ("errors", "READ ERRORS", "0", AMBER),
            ("quarantine", "QUARANTINED", "0", GREEN),
        ]:
            card = tk.Frame(cards, bg=PANEL, padx=17, pady=15, highlightthickness=1, highlightbackground=LINE)
            card.pack(side="left", fill="both", expand=True, padx=(0, 9))
            self._label(card, title, 8, MUTED, "bold", bg=PANEL).pack(anchor="w")
            var = tk.StringVar(value=value)
            self.stat_vars[key] = var
            tk.Label(card, textvariable=var, bg=PANEL, fg=color, font=("Segoe UI", 22, "bold")).pack(anchor="w", pady=(6, 0))

        actions = tk.Frame(body, bg=PANEL, padx=16, pady=14, highlightthickness=1, highlightbackground=LINE)
        actions.pack(fill="x", pady=(0, 14))
        self._label(actions, "SCAN LOCATION", 8, MUTED, "bold", bg=PANEL).pack(anchor="w")
        row = tk.Frame(actions, bg=PANEL)
        row.pack(fill="x", pady=(10, 0))
        self.scan_file_btn = self._button(row, "Scan file", self.scan_file)
        self.scan_file_btn.pack(side="left", padx=(0, 8))
        self.scan_folder_btn = self._button(row, "Scan folder", self.scan_folder, primary=True)
        self.scan_folder_btn.pack(side="left", padx=(0, 8))
        self.cancel_btn = self._button(row, "Stop scan", self.cancel_scan)
        self.cancel_btn.pack(side="left")
        self.cancel_btn.configure(state="disabled")
        self._button(row, "Quarantine", self.quarantine_selected).pack(side="right", padx=(8, 0))
        self._button(row, "Manage quarantine", self.manage_quarantine).pack(side="right")
        self._button(row, "Export CSV", self.export_report).pack(side="right", padx=(0, 8))

        progress_panel = tk.Frame(body, bg=BG)
        progress_panel.pack(fill="x", pady=(0, 14))
        self.progress_text = tk.StringVar(value="Ready. Select a file or folder to begin.")
        tk.Label(progress_panel, textvariable=self.progress_text, bg=BG, fg=MUTED,
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 7))
        self.progress = ttk.Progressbar(progress_panel, mode="indeterminate")
        self.progress.pack(fill="x")

        results_header = tk.Frame(body, bg=BG)
        results_header.pack(fill="x", pady=(4, 9))
        self._label(results_header, "Scan results", 13, TEXT, "bold", bg=BG).pack(side="left")
        self.filter_var = tk.StringVar(value="All results")
        filter_box = ttk.Combobox(results_header, textvariable=self.filter_var, state="readonly",
                                  values=("All results", "Detected", "Clean", "Errors"), width=14)
        filter_box.pack(side="right")
        filter_box.bind("<<ComboboxSelected>>", lambda _e: self._render_results())

        table_wrap = tk.Frame(body, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        table_wrap.pack(fill="both", expand=True, pady=(0, 18))
        columns = ("status", "file", "reason", "size", "hash")
        self.tree = ttk.Treeview(table_wrap, columns=columns, show="headings", selectmode="extended")
        headers = {"status": "STATUS", "file": "FILE", "reason": "DETAIL", "size": "SIZE", "hash": "SHA-256"}
        widths = {"status": 100, "file": 290, "reason": 250, "size": 85, "hash": 250}
        for col in columns:
            self.tree.heading(col, text=headers[col])
            self.tree.column(col, width=widths[col], anchor="w")
        self.tree.tag_configure("DETECTED", foreground=RED)
        self.tree.tag_configure("CLEAN", foreground=GREEN)
        self.tree.tag_configure("ERROR", foreground=AMBER)
        yscroll = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

        footer = tk.Frame(self, bg=BG, padx=28, pady=10)
        footer.pack(fill="x")
        self._label(footer, "Vanguard is an educational local scanner — keep your operating-system protection enabled.",
                    8, MUTED, bg=BG).pack(side="left")
        self._label(footer, "NO CLOUD UPLOADS", 8, MUTED, "bold", bg=BG).pack(side="right")

    def _set_scanning(self, active):
        for button in (self.scan_file_btn, self.scan_folder_btn):
            button.configure(state="disabled" if active else "normal")
        self.cancel_btn.configure(state="normal" if active else "disabled")
        if active:
            self.progress.start(10)
            self.status_pill.configure(text="●  SCANNING", fg=AMBER)
        else:
            self.progress.stop()
            self.status_pill.configure(text="●  READY", fg=GREEN)

    def scan_file(self):
        chosen = filedialog.askopenfilename(title="Choose a file to scan")
        if chosen:
            self._start_scan(Path(chosen))

    def scan_folder(self):
        chosen = filedialog.askdirectory(title="Choose a folder to scan")
        if chosen:
            self._start_scan(Path(chosen))

    def _start_scan(self, path: Path):
        if self.scan_thread and self.scan_thread.is_alive():
            return
        self.results.clear()
        self._render_results()
        self.cancel_event.clear()
        self.scan_started = datetime.now()
        self._set_scanning(True)
        self.progress_text.set(f"Scanning  ·  {path}")
        self.scan_thread = threading.Thread(target=self._scan_worker, args=(path,), daemon=True)
        self.scan_thread.start()

    def _scan_worker(self, path):
        try:
            for result in self.scanner.scan_path(
                path, excluded_dirs={QUARANTINE_DIR, LOG_DIR}, cancel_event=self.cancel_event
            ):
                if result.status == "CANCELLED":
                    break
                self.events.put(("result", result))
            self.events.put(("finished", self.cancel_event.is_set()))
        except Exception as exc:
            self.logger.exception("Scan failed")
            self.events.put(("fatal", str(exc)))

    def cancel_scan(self):
        self.cancel_event.set()
        self.progress_text.set("Stopping scan…")

    def _process_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "result":
                    self.results.append(event[1])
                    self._render_results()
                    self._refresh_stats()
                    self.progress_text.set(f"Processed {len(self.results)} file(s)")
                elif event[0] == "finished":
                    cancelled = event[1]
                    self._set_scanning(False)
                    self._refresh_stats()
                    self.progress_text.set(
                        f"Scan {'cancelled' if cancelled else 'completed'}  ·  {len(self.results)} file(s) checked"
                    )
                    self.logger.info("Scan %s: %s results", "cancelled" if cancelled else "completed", len(self.results))
                elif event[0] == "fatal":
                    self._set_scanning(False)
                    messagebox.showerror("Scan error", event[1])
        except queue.Empty:
            pass
        self.after(100, self._process_events)

    def _render_results(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        selected_filter = self.filter_var.get()
        for index, result in enumerate(self.results):
            if selected_filter == "Detected" and result.status != "DETECTED":
                continue
            if selected_filter == "Clean" and result.status != "CLEAN":
                continue
            if selected_filter == "Errors" and result.status != "ERROR":
                continue
            size = self._format_size(result.size)
            self.tree.insert("", "end", iid=str(index),
                values=(result.status, str(result.path), result.reason, size, result.sha256),
                tags=(result.status,))

    @staticmethod
    def _format_size(size):
        if size < 1024:
            return f"{size} B"
        if size < 1024**2:
            return f"{size / 1024:.1f} KB"
        if size < 1024**3:
            return f"{size / 1024**2:.1f} MB"
        return f"{size / 1024**3:.2f} GB"

    def _refresh_stats(self):
        self.stat_vars["scanned"].set(str(len(self.results)))
        self.stat_vars["detected"].set(str(sum(x.is_threat for x in self.results)))
        self.stat_vars["errors"].set(str(sum(x.status == "ERROR" for x in self.results)))
        self.stat_vars["quarantine"].set(str(len(self.quarantine.list_items())))

    def quarantine_selected(self):
        selected = self.tree.selection()
        targets = []
        for iid in selected:
            try:
                result = self.results[int(iid)]
                if result.is_threat:
                    targets.append(result)
            except (ValueError, IndexError):
                pass
        if not targets:
            messagebox.showinfo("Nothing selected", "Select one or more detected results first.")
            return
        if not messagebox.askyesno("Confirm quarantine",
            f"Move {len(targets)} detected file(s) into Vanguard quarantine?\n\n"
            "This moves files; it does not delete them. Only quarantine files you intend to isolate."):
            return
        moved = 0
        for result in targets:
            try:
                self.quarantine.quarantine(result.path, result.reason, result.sha256)
                moved += 1
            except Exception as exc:
                self.logger.exception("Quarantine failed for %s", result.path)
                messagebox.showwarning("Quarantine issue", f"{result.path}\n\n{exc}")
        messagebox.showinfo("Quarantine", f"{moved} file(s) moved.")
        self._refresh_stats()

    def manage_quarantine(self):
        win = tk.Toplevel(self)
        win.title("Vanguard — Quarantine")
        win.geometry("900x430")
        win.configure(bg=BG)
        frame = tk.Frame(win, bg=BG, padx=16, pady=16)
        frame.pack(fill="both", expand=True)
        self._label(frame, "Quarantined files", 15, TEXT, "bold", bg=BG).pack(anchor="w", pady=(0, 12))
        cols = ("name", "reason", "date", "hash")
        tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse")
        for c, title in zip(cols, ("ORIGINAL FILE", "REASON", "DATE", "SHA-256")):
            tree.heading(c, text=title)
        for c, width in zip(cols, (240, 190, 170, 240)):
            tree.column(c, width=width)
        tree.pack(fill="both", expand=True)
        items = self.quarantine.list_items()
        by_id = {}
        for item in items:
            by_id[item["id"]] = item
            tree.insert("", "end", iid=item["id"], values=(
                Path(item.get("original_path", "")).name, item.get("reason", ""),
                item.get("quarantined_at", ""), item.get("sha256", "")))
        buttons = tk.Frame(frame, bg=BG)
        buttons.pack(fill="x", pady=(12, 0))
        def restore():
            chosen = tree.selection()
            if not chosen:
                messagebox.showinfo("Select a file", "Choose an item to restore.", parent=win)
                return
            item = by_id[chosen[0]]
            if not messagebox.askyesno("Restore file",
                "Restoring a quarantined file may reintroduce a threat. Continue only if you trust it.",
                parent=win):
                return
            suggested = Path(item.get("original_path", "restored-file")).name
            destination = filedialog.asksaveasfilename(parent=win, title="Choose restore location", initialfile=suggested)
            if not destination:
                return
            try:
                self.quarantine.restore(chosen[0], Path(destination))
                messagebox.showinfo("Restored", f"File restored to:\n{destination}", parent=win)
                win.destroy()
                self._refresh_stats()
            except Exception as exc:
                messagebox.showerror("Restore failed", str(exc), parent=win)
        self._button(buttons, "Restore selected…", restore, primary=True).pack(side="left")
        self._button(buttons, "Close", win.destroy).pack(side="right")

    def export_report(self):
        if not self.results:
            messagebox.showinfo("No report", "Run a scan before exporting a report.")
            return
        destination = filedialog.asksaveasfilename(
            title="Export scan report", defaultextension=".csv",
            filetypes=[("CSV report", "*.csv")], initialfile="vanguard-scan-report.csv")
        if not destination:
            return
        try:
            with open(destination, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.writer(handle)
                writer.writerow(["status", "path", "reason", "size_bytes", "sha256"])
                for result in self.results:
                    writer.writerow([result.status, str(result.path), result.reason, result.size, result.sha256])
            messagebox.showinfo("Report exported", f"Saved report:\n{destination}")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc))


if __name__ == "__main__":
    app = VanguardApp()
    app.mainloop()
