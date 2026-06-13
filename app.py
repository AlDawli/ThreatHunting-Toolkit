"""
interfaces/desktop/app.py
──────────────────────────
Tkinter desktop GUI for the Threat Hunting Toolkit.

Uses ttk.Notebook for tabbed navigation mirroring the web interface.
Tabs: IOC Scanner · Hash · Domain · URL · Watchlist · History · Export
"""
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from datetime import datetime

from config.settings import VIRUSTOTAL_API_KEY
from core.database    import Database
from core.ioc_detector import detect_ioc_type, IOCType, friendly_name, is_hash
from core.virustotal  import VirusTotalAPI, VTError, VTAuthError, VTNotFoundError
from core.report_generator import generate_report


# ── Colour theme ──────────────────────────────────────────────────────────────
BG0      = "#060a0f"
BG1      = "#0c1220"
BG2      = "#101828"
BG3      = "#1a2540"
BORDER   = "#1e3050"
ACCENT   = "#00e5a0"
ACCENT2  = "#00b8ff"
DANGER   = "#ff4560"
WARN     = "#ffd34e"
MUTED    = "#4a6080"
TEXT     = "#c8d8ec"
TEXT_DIM = "#6a8090"
MONO     = ("Courier", 10)
MONO_SM  = ("Courier", 9)
UI_FONT  = ("Helvetica", 11)
UI_BOLD  = ("Helvetica", 11, "bold")


class DesktopApp:
    """Main Tkinter application controller."""

    def __init__(self):
        self.db  = Database()
        self.vt  = VirusTotalAPI(VIRUSTOTAL_API_KEY) if VIRUSTOTAL_API_KEY else None
        self._build_ui()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        self.root = tk.Tk()
        self.root.title("Threat Hunting Toolkit v1.0")
        self.root.configure(bg=BG0)
        self.root.geometry("1100x700")
        self.root.minsize(900, 600)

        self._style()
        self._topbar()
        self._notebook()

    def _style(self):
        s = ttk.Style()
        s.theme_use("clam")

        s.configure(".",
            background=BG1, foreground=TEXT,
            fieldbackground=BG2, troughcolor=BG1,
            selectbackground=BG3, selectforeground=ACCENT,
            font=UI_FONT)

        s.configure("TNotebook",       background=BG0, borderwidth=0)
        s.configure("TNotebook.Tab",
            background=BG1, foreground=TEXT_DIM,
            padding=[14, 6], font=("Helvetica", 10, "bold"))
        s.map("TNotebook.Tab",
            background=[("selected", BG2)],
            foreground=[("selected", ACCENT)])

        s.configure("TFrame",    background=BG1)
        s.configure("TLabel",    background=BG1, foreground=TEXT, font=UI_FONT)
        s.configure("TButton",   background=BG3, foreground=TEXT, font=UI_BOLD, relief="flat")
        s.map("TButton",
            background=[("active", BG2), ("pressed", ACCENT)],
            foreground=[("active", ACCENT)])

        s.configure("Accent.TButton", background=ACCENT, foreground=BG0, font=UI_BOLD)
        s.map("Accent.TButton",
            background=[("active", "#00c888"), ("pressed", "#009966")])

        s.configure("Treeview",
            background=BG2, fieldbackground=BG2,
            foreground=TEXT, rowheight=24, font=MONO_SM)
        s.configure("Treeview.Heading",
            background=BG3, foreground=MUTED, font=("Helvetica", 9, "bold"))
        s.map("Treeview",
            background=[("selected", BG3)],
            foreground=[("selected", ACCENT)])

    def _topbar(self):
        bar = tk.Frame(self.root, bg=BG1, height=46)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)

        tk.Label(bar, text="⬡ THREAT HUNTING TOOLKIT",
                 bg=BG1, fg=ACCENT,
                 font=("Courier", 13, "bold")).pack(side="left", padx=16, pady=8)

        status_color = ACCENT if VIRUSTOTAL_API_KEY else DANGER
        status_text  = (f"⬤ VT KEY: {VIRUSTOTAL_API_KEY[:6]}…"
                        if VIRUSTOTAL_API_KEY else "⬤ VT KEY NOT SET — add to .env")
        tk.Label(bar, text=status_text, bg=BG1, fg=status_color,
                 font=("Courier", 10)).pack(side="right", padx=16)

    def _notebook(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=0, pady=0)

        self._tab_scanner(nb)
        self._tab_hash(nb)
        self._tab_domain(nb)
        self._tab_url(nb)
        self._tab_watchlist(nb)
        self._tab_history(nb)
        self._tab_export(nb)

        nb.bind("<<NotebookTabChanged>>", self._on_tab_change)

    def _on_tab_change(self, event):
        nb   = event.widget
        name = nb.tab(nb.select(), "text").strip()
        if "History"   in name: self._load_history()
        if "Watchlist" in name: self._load_watchlist()

    # ── Helper widgets ────────────────────────────────────────────────────────

    def _frame(self, parent) -> ttk.Frame:
        f = ttk.Frame(parent)
        f.configure(style="TFrame")
        return f

    def _label(self, parent, text, color=TEXT, font=UI_FONT) -> tk.Label:
        return tk.Label(parent, text=text, bg=BG1, fg=color, font=font)

    def _entry(self, parent, width=60) -> tk.Entry:
        e = tk.Entry(parent, bg=BG2, fg=TEXT, insertbackground=ACCENT,
                     relief="flat", font=("Courier", 11),
                     highlightthickness=1, highlightbackground=BORDER,
                     highlightcolor=ACCENT, width=width)
        return e

    def _btn(self, parent, text, cmd, accent=False) -> ttk.Button:
        style = "Accent.TButton" if accent else "TButton"
        return ttk.Button(parent, text=text, command=cmd, style=style)

    def _output(self, parent, height=18) -> scrolledtext.ScrolledText:
        st = scrolledtext.ScrolledText(parent,
            bg=BG2, fg=TEXT, insertbackground=ACCENT,
            font=("Courier", 10), relief="flat",
            wrap="word", height=height,
            selectbackground=BG3, selectforeground=ACCENT)
        st.configure(state="disabled")
        st.tag_configure("accent",  foreground=ACCENT)
        st.tag_configure("danger",  foreground=DANGER)
        st.tag_configure("warn",    foreground=WARN)
        st.tag_configure("ok",      foreground=ACCENT)
        st.tag_configure("muted",   foreground=MUTED)
        st.tag_configure("heading", foreground=ACCENT, font=("Courier", 11, "bold"))
        return st

    def _write(self, widget: scrolledtext.ScrolledText,
               text: str, tag: str = "") -> None:
        widget.configure(state="normal")
        widget.insert("end", text, tag)
        widget.see("end")
        widget.configure(state="disabled")

    def _clear(self, widget: scrolledtext.ScrolledText) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.configure(state="disabled")

    # ── Tabs ──────────────────────────────────────────────────────────────────

    def _scan_ui(self, nb, tab_label, placeholder):
        """Shared layout for scanner / hash / domain / url tabs."""
        frame = self._frame(nb)
        nb.add(frame, text=f"  {tab_label}  ")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(2, weight=1)

        # Input row
        row = tk.Frame(frame, bg=BG1, pady=10, padx=12)
        row.grid(row=0, column=0, sticky="ew")
        row.columnconfigure(0, weight=1)

        entry = self._entry(row)
        entry.insert(0, placeholder)
        entry.config(fg=MUTED)

        def on_focus_in(e):
            if entry.get() == placeholder:
                entry.delete(0, "end"); entry.config(fg=TEXT)
        def on_focus_out(e):
            if not entry.get():
                entry.insert(0, placeholder); entry.config(fg=MUTED)

        entry.bind("<FocusIn>",  on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)
        entry.grid(row=0, column=0, sticky="ew", ipady=6, padx=(0,8))

        output = self._output(frame)

        def do_scan(_event=None):
            val = entry.get().strip()
            if not val or val == placeholder: return
            self._run_analysis(val, output)

        entry.bind("<Return>", do_scan)
        btn = self._btn(row, "  SCAN  ", do_scan, accent=True)
        btn.grid(row=0, column=1)

        # Separator
        sep = tk.Frame(frame, bg=BORDER, height=1)
        sep.grid(row=1, column=0, sticky="ew")

        output.grid(row=2, column=0, sticky="nsew", padx=0, pady=0)
        return frame

    def _tab_scanner(self, nb):
        self._scan_ui(nb, "⬡ IOC Scanner",
                      "Enter IP, domain, URL, MD5, SHA-1 or SHA-256…")

    def _tab_hash(self, nb):
        self._scan_ui(nb, "◈ Hash Checker",
                      "Enter MD5, SHA-1 or SHA-256 hash…")

    def _tab_domain(self, nb):
        self._scan_ui(nb, "◎ Domain Rep.",
                      "Enter domain name (e.g. evil-site.com)…")

    def _tab_url(self, nb):
        self._scan_ui(nb, "⊞ URL Analysis",
                      "Enter full URL (https://…)…")

    def _tab_watchlist(self, nb):
        frame = self._frame(nb)
        nb.add(frame, text="  ☰ Watchlist  ")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        # Add IOC form
        add_frame = tk.Frame(frame, bg=BG1, pady=10, padx=12)
        add_frame.grid(row=0, column=0, sticky="ew")

        self._label(add_frame, "IOC:", font=("Helvetica", 10)).grid(row=0, column=0, padx=(0,4))
        self._wl_ioc_entry = self._entry(add_frame, width=36)
        self._wl_ioc_entry.grid(row=0, column=1, ipady=4, padx=(0,10))

        self._label(add_frame, "Tags:", font=("Helvetica", 10)).grid(row=0, column=2, padx=(0,4))
        self._wl_tag_entry = self._entry(add_frame, width=18)
        self._wl_tag_entry.grid(row=0, column=3, ipady=4, padx=(0,10))

        self._label(add_frame, "Notes:", font=("Helvetica", 10)).grid(row=0, column=4, padx=(0,4))
        self._wl_note_entry = self._entry(add_frame, width=22)
        self._wl_note_entry.grid(row=0, column=5, ipady=4, padx=(0,10))

        self._btn(add_frame, "+ Add", self._add_watchlist_ioc, accent=True).grid(row=0, column=6)

        # Treeview
        cols = ("ioc", "type", "tags", "notes", "added")
        self._wl_tree = ttk.Treeview(frame, columns=cols, show="headings", height=20)
        for col, w, label in [
            ("ioc",   320, "IOC"),
            ("type",   80, "TYPE"),
            ("tags",  120, "TAGS"),
            ("notes", 180, "NOTES"),
            ("added",  95, "ADDED"),
        ]:
            self._wl_tree.heading(col, text=label)
            self._wl_tree.column(col, width=w, stretch=(col == "ioc"))

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self._wl_tree.yview)
        self._wl_tree.configure(yscrollcommand=vsb.set)
        self._wl_tree.grid(row=1, column=0, sticky="nsew")
        vsb.grid(row=1, column=1, sticky="ns")

        # Bottom bar
        bot = tk.Frame(frame, bg=BG1, pady=6, padx=12)
        bot.grid(row=2, column=0, sticky="ew")
        self._btn(bot, "🗑 Delete Selected", self._delete_watchlist_ioc).pack(side="left")
        self._btn(bot, "⬡ Scan Selected",    self._scan_watchlist_ioc, accent=True).pack(side="left", padx=8)
        self._btn(bot, "↺ Refresh",          self._load_watchlist).pack(side="right")

    def _tab_history(self, nb):
        frame = self._frame(nb)
        nb.add(frame, text="  ◷ History  ")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        cols = ("query", "type", "verdict", "mal", "sus", "timestamp")
        self._hist_tree = ttk.Treeview(frame, columns=cols, show="headings", height=28)

        for col, w, label in [
            ("query",     340, "IOC / QUERY"),
            ("type",       80, "TYPE"),
            ("verdict",    90, "VERDICT"),
            ("mal",        50, "MAL"),
            ("sus",        50, "SUS"),
            ("timestamp", 160, "TIMESTAMP"),
        ]:
            self._hist_tree.heading(col, text=label)
            self._hist_tree.column(col, width=w, stretch=(col == "query"))

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self._hist_tree.yview)
        self._hist_tree.configure(yscrollcommand=vsb.set)
        self._hist_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        bot = tk.Frame(frame, bg=BG1, pady=6, padx=12)
        bot.grid(row=1, column=0, sticky="ew")
        self._btn(bot, "Clear History", self._clear_history).pack(side="left")
        self._btn(bot, "↺ Refresh",     self._load_history).pack(side="right")

    def _tab_export(self, nb):
        frame = self._frame(nb)
        nb.add(frame, text="  ⬕ Export  ")

        inner = tk.Frame(frame, bg=BG1)
        inner.place(relx=0.5, rely=0.45, anchor="center")

        self._label(inner, "⬕ Export PDF Report",
                    color=ACCENT, font=("Helvetica", 16, "bold")).pack(pady=(0,8))
        self._label(inner, "Generates a full intelligence report from your\n"
                    "search history and IOC watchlist.",
                    color=TEXT_DIM, font=("Helvetica", 10)).pack(pady=(0,20))

        self._btn(inner, "  ⬕  Generate & Save PDF Report  ",
                  self._export_report, accent=True).pack(pady=6, ipadx=10, ipady=6)

        self._export_status = self._label(inner, "", color=MUTED, font=("Helvetica", 10))
        self._export_status.pack(pady=8)

    # ── Analysis logic ────────────────────────────────────────────────────────

    def _run_analysis(self, query: str, output: scrolledtext.ScrolledText):
        """Run VT lookup in a background thread, then update the output widget."""
        if not self.vt:
            self._clear(output)
            self._write(output, "ERROR: VirusTotal API key not configured.\n"
                        "Add VT_API_KEY=<your_key> to the .env file.\n", "danger")
            return

        ioc_type = detect_ioc_type(query)

        self._clear(output)
        self._write(output, f"⬡ Scanning: {query}\n", "accent")
        self._write(output, f"  Detected type : {friendly_name(ioc_type)}\n", "muted")
        self._write(output, f"  Querying VirusTotal (free tier ≈15s delay)…\n\n", "muted")

        def worker():
            try:
                if is_hash(ioc_type):
                    result = self.vt.check_hash(query)
                elif ioc_type == IOCType.DOMAIN:
                    result = self.vt.check_domain(query)
                elif ioc_type == IOCType.IP:
                    result = self.vt.check_ip(query)
                elif ioc_type == IOCType.URL:
                    result = self.vt.check_url(query)
                else:
                    self.root.after(0, lambda: (
                        self._write(output, f"ERROR: Unknown or unsupported IOC type.\n", "danger")
                    ))
                    return

                self.db.log_search(query, ioc_type.value, result.raw)
                self.root.after(0, lambda: self._render_result(output, result, query))

            except VTNotFoundError as e:
                self.root.after(0, lambda: self._write(output, f"NOT FOUND: {e}\n", "warn"))
            except VTError as e:
                self.root.after(0, lambda: self._write(output, f"API ERROR: {e}\n", "danger"))
            except Exception as e:
                self.root.after(0, lambda: self._write(output, f"ERROR: {e}\n", "danger"))

        threading.Thread(target=worker, daemon=True).start()

    def _render_result(self, output, result, query):
        from core.virustotal import ParsedResult
        r: ParsedResult = result

        verdict_tag = {"MALICIOUS":"danger","SUSPICIOUS":"warn","CLEAN":"ok"}.get(r.verdict,"muted")

        self._write(output, "═" * 60 + "\n", "muted")
        self._write(output, f"  VERDICT : ", "muted")
        self._write(output, f"{r.verdict}\n", verdict_tag)
        self._write(output, "═" * 60 + "\n\n", "muted")

        self._write(output, "DETECTION STATS\n", "heading")
        self._write(output, f"  Malicious  : {r.malicious}\n",  "danger")
        self._write(output, f"  Suspicious : {r.suspicious}\n", "warn")
        self._write(output, f"  Harmless   : {r.harmless}\n",   "ok")
        self._write(output, f"  Undetected : {r.undetected}\n", "muted")
        self._write(output, f"  Total      : {r.total}\n\n",    "muted")
        self._write(output, f"  Reputation : {r.reputation:+d}\n\n", "muted")

        if r.extra:
            self._write(output, "IOC DETAILS\n", "heading")
            for k, v in r.extra.items():
                if v and v != "—" and v != 0:
                    val = str(v) if not isinstance(v, dict) else str(v)
                    self._write(output, f"  {k.replace('_',' ').upper():<18}: {val[:100]}\n", "")

        if r.tags:
            self._write(output, f"\n  Tags: {', '.join(r.tags)}\n", "accent")

        if r.detections:
            self._write(output, f"\nDETECTIONS ({len(r.detections)})\n", "heading")
            for d in r.detections:
                tag = "danger" if d["category"] == "malicious" else "warn"
                self._write(output, f"  [{d['category'].upper():<10}] ", tag)
                self._write(output, f"{d['engine']:<24} → {d['result']}\n", "")

        self._write(output, "\n" + "═" * 60 + "\n", "muted")

    # ── Watchlist actions ─────────────────────────────────────────────────────

    def _load_watchlist(self):
        for row in self._wl_tree.get_children():
            self._wl_tree.delete(row)
        for ioc in self.db.get_iocs():
            self._wl_tree.insert("", "end", iid=str(ioc["id"]), values=(
                ioc["ioc"], ioc["ioc_type"].upper(),
                ioc.get("tags",""), ioc.get("notes",""),
                (ioc.get("added_at",""))[:10],
            ))

    def _add_watchlist_ioc(self):
        ioc   = self._wl_ioc_entry.get().strip()
        tags  = self._wl_tag_entry.get().strip()
        notes = self._wl_note_entry.get().strip()
        if not ioc:
            messagebox.showwarning("Input required", "Enter an IOC value."); return
        ioc_type = detect_ioc_type(ioc).value
        if self.db.add_ioc(ioc, ioc_type, tags, notes):
            self._wl_ioc_entry.delete(0,"end")
            self._load_watchlist()
        else:
            messagebox.showinfo("Duplicate", f"'{ioc}' is already in the watchlist.")

    def _delete_watchlist_ioc(self):
        sel = self._wl_tree.selection()
        if not sel:
            messagebox.showwarning("None selected", "Select a row to delete."); return
        if not messagebox.askyesno("Confirm", f"Delete {len(sel)} IOC(s)?", icon="warning"):
            return
        for iid in sel:
            self.db.delete_ioc(int(iid))
        self._load_watchlist()

    def _scan_watchlist_ioc(self):
        sel = self._wl_tree.selection()
        if not sel:
            messagebox.showwarning("None selected", "Select an IOC to scan."); return
        ioc = self._wl_tree.item(sel[0])["values"][0]
        messagebox.showinfo("Scan IOC",
            f"Switch to the IOC Scanner tab and paste:\n\n{ioc}")

    # ── History actions ───────────────────────────────────────────────────────

    def _load_history(self):
        for row in self._hist_tree.get_children():
            self._hist_tree.delete(row)
        for h in self.db.get_history(200):
            self._hist_tree.insert("", "end", values=(
                h["query"], h["ioc_type"].upper(), h["verdict"],
                h["malicious_count"], h["suspicious_count"],
                h["timestamp"][:19],
            ))

    def _clear_history(self):
        if messagebox.askyesno("Confirm", "Clear all search history?", icon="warning"):
            self.db.clear_history()
            self._load_history()

    # ── Export ────────────────────────────────────────────────────────────────

    def _export_report(self):
        self._export_status.config(text="Generating PDF…", fg=MUTED)
        self.root.update()

        def worker():
            try:
                searches = self.db.get_history(200)
                iocs     = self.db.get_iocs()
                path     = generate_report(searches, iocs)
                self.root.after(0, lambda: self._export_done(str(path)))
            except Exception as e:
                self.root.after(0, lambda: self._export_status.config(
                    text=f"Export failed: {e}", fg=DANGER))

        threading.Thread(target=worker, daemon=True).start()

    def _export_done(self, path: str):
        self._export_status.config(text=f"✓ Saved: {path}", fg=ACCENT)
        if messagebox.askyesno("Report Ready", f"PDF saved to:\n{path}\n\nOpen it now?"):
            import subprocess, sys
            opener = "open" if sys.platform == "darwin" else (
                     "start" if sys.platform == "win32" else "xdg-open")
            subprocess.Popen([opener, path])

    # ── Run ───────────────────────────────────────────────────────────────────

    def run(self):
        self.root.mainloop()
