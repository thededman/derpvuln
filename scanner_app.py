"""Tkinter GUI for the network scanner application."""

from __future__ import annotations

import os
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from scanner_core import (
    ScanConfig,
    ScanError,
    ensure_nmap_available,
    example_targets,
    resolve_default_output,
    run_scan_in_thread,
    validate_target,
)


class ScannerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Network Scanner")
        self.geometry("720x480")
        self.resizable(True, True)

        self.target_var = tk.StringVar(value="192.168.1.0/24")
        self.output_var = tk.StringVar(value=str(resolve_default_output()))
        self.use_wsl_var = tk.BooleanVar(value=True)
        self.vuln_var = tk.BooleanVar(value=True)

        self._build_ui()

    def _build_ui(self) -> None:
        frame = ttk.Frame(self, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)

        title = ttk.Label(frame, text="Network Scanner", font=("Segoe UI", 16, "bold"))
        title.grid(row=0, column=0, columnspan=3, sticky="w")

        ttk.Label(frame, text="Target range or IP:").grid(row=1, column=0, sticky="w", pady=(12, 0))
        target_entry = ttk.Entry(frame, textvariable=self.target_var, width=40)
        target_entry.grid(row=1, column=1, sticky="ew", pady=(12, 0))
        ttk.Label(frame, text=example_targets()).grid(row=1, column=2, sticky="w", padx=8, pady=(12, 0))

        ttk.Label(frame, text="Output folder:").grid(row=2, column=0, sticky="w", pady=(8, 0))
        output_entry = ttk.Entry(frame, textvariable=self.output_var, width=40)
        output_entry.grid(row=2, column=1, sticky="ew", pady=(8, 0))
        ttk.Button(frame, text="Browse", command=self._choose_output).grid(row=2, column=2, sticky="w", padx=8, pady=(8, 0))

        options_frame = ttk.LabelFrame(frame, text="Options", padding=8)
        options_frame.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(12, 0))

        ttk.Checkbutton(options_frame, text="Use WSL (recommended for Kali tools)", variable=self.use_wsl_var).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(options_frame, text="Run vulnerability scan (nmap scripts)", variable=self.vuln_var).grid(row=1, column=0, sticky="w")

        self.scan_button = ttk.Button(frame, text="Run Scan", command=self._run_scan)
        self.scan_button.grid(row=4, column=0, sticky="w", pady=(12, 0))
        ttk.Button(frame, text="Open Reports Folder", command=self._open_reports).grid(row=4, column=1, sticky="w", pady=(12, 0))

        self.log = scrolledtext.ScrolledText(frame, height=12)
        self.log.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=(12, 0))

        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(5, weight=1)

    def _choose_output(self) -> None:
        selected = filedialog.askdirectory(initialdir=self.output_var.get())
        if selected:
            self.output_var.set(selected)

    def _open_reports(self) -> None:
        path = Path(self.output_var.get())
        if not path.exists():
            messagebox.showinfo("Reports", "No reports folder exists yet.")
            return
        os.startfile(path)  # type: ignore[attr-defined]

    def _run_scan(self) -> None:
        self.log.delete("1.0", tk.END)
        self.scan_button.config(state=tk.DISABLED)

        target = self.target_var.get().strip()
        output_dir = Path(self.output_var.get()).expanduser()
        use_wsl = self.use_wsl_var.get()
        run_vuln = self.vuln_var.get()

        try:
            validate_target(target)
            ensure_nmap_available(use_wsl)
        except ScanError as exc:
            self.scan_button.config(state=tk.NORMAL)
            messagebox.showerror("Validation error", str(exc))
            return

        config = ScanConfig(
            target=target,
            output_dir=output_dir,
            use_wsl=use_wsl,
            run_vuln_scan=run_vuln,
        )

        def logger(message: str) -> None:
            self.log.insert(tk.END, message + "\n")
            self.log.see(tk.END)

        def on_finish(result, error) -> None:
            self.scan_button.config(state=tk.NORMAL)
            if error:
                messagebox.showerror("Scan failed", str(error))
                return
            if result:
                messagebox.showinfo(
                    "Scan complete",
                    f"Reports saved to {result.discovery_html.parent}",
                )

        run_scan_in_thread(config, logger, on_finish)


def main() -> None:
    app = ScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()