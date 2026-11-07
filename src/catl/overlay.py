"""Trusted, minimisable desktop overlay with protected broker-IPC mode.

Dependencies: Python's optional tkinter/Tcl installation. This GUI must run under a
trusted desktop identity with access to the supervisor's private state directory.
It DOES NOT authenticate a human independently of the trusted OS operator account.
"""
from __future__ import annotations

import getpass
import json
from pathlib import Path
from typing import Any
from .crypto import get_or_create_key
from .policy import Policy
from .store import State

BG = "#0b1118"
PANEL = "#14202b"
ACCENT = "#41edbd"
TEXT = "#f1f5f9"
MUTED = "#9fb1c3"
RED = "#ff7a7a"
BUTTON = "#25364a"
FEATURES = (
    ("gateway_enabled", "🛡️  Gateway execution", "OFF blocks all new tool calls"),
    ("approvals_enabled", "✋  Human approvals", "OFF blocks approval-required actions"),
    ("verification_enabled", "🔎  File verification", "OFF blocks actions requiring verification"),
    ("audit_enabled", "🧾  Audit evidence", "OFF blocks all new tool calls"),
)


class OperatorOverlay:
    def __init__(self, root, state: State, policy: Policy, *, topmost: bool = True):
        import tkinter as tk
        from tkinter import messagebox, simpledialog
        self.tk = tk
        self.messagebox = messagebox
        self.simpledialog = simpledialog
        self.root = root
        self.state = state
        self.policy = policy
        self.actor = getpass.getuser() or "desktop-operator"
        self.compact = False
        self._closed = False
        self.root.title("CATL · Local Agent Controls")
        self.root.configure(bg=BG)
        self.root.geometry("465x800+60+80")
        self.root.minsize(390, 104)
        self.root.attributes("-topmost", topmost)
        self.root.protocol("WM_DELETE_WINDOW", self.root.iconify)
        self._container = tk.Frame(root, bg=BG)
        self._container.pack(fill="both", expand=True)
        head = tk.Frame(self._container, bg=BG)
        head.pack(fill="x", padx=16, pady=(13, 4))
        tk.Label(head, text="◉  CALEDAPT", fg=ACCENT, bg=BG,
                 font=("Segoe UI", 14, "bold")).pack(side="left")
        tk.Button(head, text="—", command=self.root.iconify, bg=BUTTON, fg=TEXT,
                  width=3, relief="flat").pack(side="right", padx=(5, 0))
        tk.Button(head, text="✕", command=self.root.destroy, bg=BUTTON, fg=TEXT,
                  width=3, relief="flat").pack(side="right", padx=(5, 0))
        self._compact_btn = tk.Button(head, text="▤", command=self.toggle_compact,
                  bg=BUTTON, fg=TEXT, width=3, relief="flat")
        self._compact_btn.pack(side="right", padx=(5, 0))
        self.status_var = tk.StringVar(value="Checking protected controls...")
        self.status = tk.Label(self._container, textvariable=self.status_var,
                              fg=ACCENT, bg=BG, anchor="w", font=("Segoe UI", 10, "bold"))
        self.status.pack(fill="x", padx=18, pady=(0, 6))
        self.quick = tk.Frame(self._container, bg=BG)
        self.quick.pack(fill="x", padx=15, pady=(0, 8))
        tk.Button(self.quick, text="⛔  PAUSE AGENTS", command=lambda: self.toggle_feature("gateway_enabled", False),
                  bg="#783d4d", fg="white", relief="flat", padx=12, pady=8).pack(side="left", fill="x", expand=True, padx=(0, 6))
        tk.Button(self.quick, text="▶  RESUME", command=lambda: self.toggle_feature("gateway_enabled", True),
                  bg="#1b6157", fg="white", relief="flat", padx=12, pady=8).pack(side="left", fill="x", expand=True)
        self.body = tk.Frame(self._container, bg=BG)
        self.body.pack(fill="both", expand=True)
        # All sections must remain accessible on short desktop displays.
        # Previous fixed-height layout shrank the approvals queue to ~3px.
        self.body_canvas = tk.Canvas(self.body, bg=BG, highlightthickness=0)
        self.body_scrollbar = tk.Scrollbar(self.body, orient="vertical",
                                           command=self.body_canvas.yview)
        self.body_canvas.configure(yscrollcommand=self.body_scrollbar.set)
        self.body_scrollbar.pack(side="right", fill="y")
        self.body_canvas.pack(side="left", fill="both", expand=True)
        self.content = tk.Frame(self.body_canvas, bg=BG)
        content_id = self.body_canvas.create_window((0, 0), window=self.content, anchor="nw")
        self.content.bind("<Configure>", lambda _ev: self.body_canvas.configure(
            scrollregion=self.body_canvas.bbox("all")))
        self.body_canvas.bind("<Configure>", lambda ev: self.body_canvas.itemconfigure(
            content_id, width=ev.width))
        self._heading(self.content, "SECURITY FEATURES")
        self.feature_vars: dict[str, Any] = {}
        feature_frame = tk.Frame(self.content, bg=PANEL, padx=12, pady=8)
        feature_frame.pack(fill="x", padx=15)
        for name, title, description in FEATURES:
            group = tk.Frame(feature_frame, bg=PANEL)
            group.pack(fill="x", pady=(3, 5))
            var = tk.BooleanVar(value=False)
            self.feature_vars[name] = var
            tk.Checkbutton(group, text=title, variable=var, command=lambda n=name, v=var: self.toggle_feature(n, v.get()),
                           bg=PANEL, activebackground=PANEL, fg=TEXT, selectcolor=BG, activeforeground=ACCENT,
                           highlightthickness=0, font=("Segoe UI", 10, "bold")).pack(anchor="w")
            tk.Label(group, text=description, bg=PANEL, fg=MUTED,
                     font=("Segoe UI", 9)).pack(anchor="w", padx=(26, 0))
        self._heading(self.content, "PER-TOOL CONTROLS")
        tool_shell = tk.Frame(self.content, bg=PANEL)
        tool_shell.pack(fill="x", padx=15)
        canvas = tk.Canvas(tool_shell, bg=PANEL, height=140, highlightthickness=0)
        scroll = tk.Scrollbar(tool_shell, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        tool_wrap = tk.Frame(canvas, bg=PANEL)
        window_id = canvas.create_window((0, 0), window=tool_wrap, anchor="nw")
        tool_wrap.bind("<Configure>", lambda _ev: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda ev: canvas.itemconfigure(window_id, width=ev.width))
        self.tool_vars: dict[str, Any] = {}
        for tool in sorted(policy.tool_pins):
            var = tk.BooleanVar(value=False)
            self.tool_vars[tool] = var
            tk.Checkbutton(tool_wrap, text="🔌  " + tool, variable=var,
                command=lambda n=tool, v=var: self.toggle_tool(n, v.get()),
                bg=PANEL, activebackground=PANEL, fg=TEXT, selectcolor=BG,
                activeforeground=ACCENT, highlightthickness=0,
                font=("Consolas", 10)).pack(anchor="w", padx=10, pady=4)
        if not policy.tool_pins:
            tk.Label(tool_wrap,text="No pinned tools in the policy",bg=PANEL, fg=MUTED).pack(padx=12,pady=7)
        tools_buttons = tk.Frame(self.content, bg=BG)
        tools_buttons.pack(fill="x",padx=15,pady=4)
        tk.Button(tools_buttons,text="Disable all tools",bg=BUTTON,fg=TEXT,relief="flat",
                  command=lambda:self.toggle_all_tools(False)).pack(side="left",fill="x",expand=True,padx=(0,5))
        tk.Button(tools_buttons,text="Enable pinned tools",bg=BUTTON,fg=TEXT,relief="flat",
                  command=lambda:self.toggle_all_tools(True)).pack(side="left",fill="x",expand=True)
        self._heading(self.content, "⚠️  QUARANTINED / UNCERTAIN ACTIONS")
        incident_frame = tk.Frame(self.content, bg=PANEL, padx=8, pady=7)
        incident_frame.pack(fill="x", padx=15, pady=(0, 5))
        self.incident_list = tk.Listbox(incident_frame, height=3, bg=BG, fg=RED,
            selectbackground="#75404b", selectforeground=TEXT, borderwidth=0,
            highlightthickness=0, font=("Consolas", 9))
        self.incident_list.pack(fill="x")
        tk.Button(incident_frame, text="🔎  Resolve selected after checking external effect",
                  command=self.reconcile_selected, bg=BUTTON, fg=TEXT, relief="flat",
                  padx=9, pady=5).pack(fill="x", pady=(5,0))
        self._incidents: list[dict[str, Any]] = []
        self._heading(self.content, "HUMAN APPROVAL QUEUE")
        queue_frame = tk.Frame(self.content, bg=PANEL, padx=8, pady=8)
        queue_frame.pack(fill="both", expand=True, padx=15, pady=(0, 10))
        self.pending = tk.Listbox(queue_frame, height=5, bg=BG, fg=TEXT,
            selectbackground="#246c60", selectforeground=TEXT, borderwidth=0, highlightthickness=0,
            font=("Consolas", 9))
        self.pending.pack(fill="both", expand=True)
        self.pending.bind("<<ListboxSelect>>", lambda _event: self.update_details())
        self.detail = tk.Label(queue_frame, text="Select an approval to inspect the exact arguments.",
                               bg=PANEL, fg=MUTED, anchor="w", justify="left", wraplength=390,
                               font=("Segoe UI", 9))
        self.detail.pack(fill="x", pady=5)
        approve_row = tk.Frame(queue_frame, bg=PANEL)
        approve_row.pack(fill="x")
        tk.Button(approve_row, text="✓  Approve selected", command=lambda: self.decide_selected(True),
                  bg="#1a6358", fg=TEXT, relief="flat", padx=9, pady=6).pack(side="left", fill="x", expand=True, padx=(0, 6))
        tk.Button(approve_row, text="✕  Reject selected", command=lambda: self.decide_selected(False),
                  bg="#743d4b", fg=TEXT, relief="flat", padx=9, pady=6).pack(side="left", fill="x", expand=True)
        foot = tk.Label(self.content,
            text="LOCAL ONLY · NO NETWORK · Missing/tampered controls fail closed",
            bg=BG, fg=MUTED, font=("Segoe UI", 8), wraplength=430)
        foot.pack(pady=(0, 8))
        self._rows: list[dict[str, Any]] = []
        self.refresh()

    def _heading(self, parent, title: str) -> None:
        self.tk.Label(parent, text=title, bg=BG, fg=MUTED, anchor="w",
            font=("Segoe UI", 9, "bold")).pack(fill="x", padx=17, pady=(9, 5))

    def toggle_compact(self) -> None:
        self.compact = not self.compact
        if self.compact:
            self.body.pack_forget()
            self.root.geometry("465x110")
        else:
            self.body.pack(fill="both", expand=True)
            self.root.geometry("465x800")

    def toggle_feature(self, name: str, enabled: bool) -> None:
        try:
            self.state.set_feature(name, bool(enabled), self.actor)
        except (ValueError, PermissionError, OSError) as exc:
            self.messagebox.showerror("Control update blocked", f"{type(exc).__name__}: {exc}")
        self.refresh()

    def toggle_tool(self, tool: str, enabled: bool) -> None:
        try:
            self.state.set_tool(tool, bool(enabled), self.actor, set(self.policy.tool_pins))
        except (ValueError, PermissionError, OSError) as exc:
            self.messagebox.showerror("Tool update blocked", f"{type(exc).__name__}: {exc}")
        self.refresh()

    def toggle_all_tools(self, enabled: bool) -> None:
        try:
            self.state.set_all_tools(enabled, self.actor, set(self.policy.tool_pins))
        except (ValueError, PermissionError, OSError) as exc:
            self.messagebox.showerror("Tool update blocked", f"{type(exc).__name__}: {exc}")
        self.refresh()

    def reconcile_selected(self) -> None:
        selection = self.incident_list.curselection()
        if not selection or selection[0] >= len(self._incidents):
            self.messagebox.showinfo("Select incident", "Choose an uncertain action first.")
            return
        incident = self._incidents[selection[0]]
        reference = self.simpledialog.askstring("External evidence required",
            "Enter ticket:, readback: or incident: reference (no spaces/credentials).\n"
            "CATL cannot automatically prove the external effect.", parent=self.root)
        if not reference:
            return
        if not self.messagebox.askyesno("Confirm manual reconciliation",
                "Only continue after checking the external system yourself.\n\n"
                f"Tool: {incident['tool']}\nAction: {incident['action_id']}\n"
                f"Status: {incident['status']}\nEvidence: {reference}\n\n"
                "This allows future actions; it NEVER retries the previous action.",
                default="no"):
            return
        try:
            accepted = self.state.reconcile_incident(incident['action_id'], self.actor,
                reference, "I_HAVE_RECONCILED_THE_EXTERNAL_EFFECT")
            if not accepted:
                self.messagebox.showwarning("No longer pending", "The incident was already resolved.")
        except (ValueError, PermissionError, OSError) as exc:
            self.messagebox.showerror("Reconciliation blocked", f"{type(exc).__name__}: {exc}")
        self.refresh()

    def _selection(self) -> dict[str, Any] | None:
        selection = self.pending.curselection()
        return self._rows[selection[0]] if selection and selection[0] < len(self._rows) else None

    def update_details(self) -> None:
        row = self._selection()
        if row is None:
            self.detail.configure(text="Select an approval to inspect the exact arguments.")
            return
        detail = row.get("detail", {})
        content = json.dumps(detail, indent=2, ensure_ascii=False)
        self.detail.configure(text=content[:280] + ("…" if len(content) > 280 else ""))

    def decide_selected(self, approve: bool) -> None:
        selected = self._selection()
        if selected is None:
            self.messagebox.showinfo("Select a request", "Choose a pending request first.")
            return
        phrase = "APPROVE" if approve else "REJECT"
        # An explicit human confirmation displays full original request details.
        details = json.dumps(selected.get("detail", {}), indent=2, ensure_ascii=False)
        if not self.messagebox.askyesno(f"Confirm {phrase}",
              f"{phrase} this precise tool call?\n\nID: {selected['id']}\n\n{details[:5000]}",
              default="no"):
            return
        try:
            ok = self.state.decide(selected["id"], self.actor, approve)
            if not ok:
                self.messagebox.showwarning("No longer available", "The request expired or was already decided.")
        except (ValueError, PermissionError, OSError) as exc:
            self.messagebox.showerror("Approval blocked", f"{type(exc).__name__}: {exc}")
        self.refresh()

    def refresh(self) -> None:
        if self._closed:
            return
        try:
            controls = self.state.controls()
            for name, var in self.feature_vars.items():
                var.set(controls[name])
            disabled = set(controls["disabled_tools"])
            previous = {item['action_id'] for item in self._incidents}
            self._incidents = self.state.open_incidents()
            quarantined = {item['tool'] for item in self._incidents}
            self.incident_list.delete(0, self.tk.END)
            for item in self._incidents:
                self.incident_list.insert(self.tk.END,
                    f"⛔ {item['tool']} · {item['status']} · {item['action_id'][:8]}")
            for name, var in self.tool_vars.items():
                var.set(name not in disabled and name not in quarantined)
            active = controls["gateway_enabled"] and controls["audit_enabled"]
            status = ("● ARMED — permitted calls may execute" if active else "⛔ PAUSED — new tool calls blocked")
            if self._incidents:
                status += f"  |  {len(self._incidents)} ⚠️ quarantined"
            self.status_var.set(status)
            self.status.configure(fg=ACCENT if active else RED)
            selection = self._selection()
            selected_id = selection["id"] if selection else None
            self._rows = self.state.list_pending()
            self.pending.delete(0, self.tk.END)
            new_idx = None
            for idx, item in enumerate(self._rows):
                label = f"{item['detail'].get('tool','?')}  ·  {item['id'][:12]}…"
                self.pending.insert(self.tk.END, label)
                if item["id"] == selected_id:
                    new_idx = idx
            if new_idx is not None:
                self.pending.selection_set(new_idx)
            self.update_details()
        except (ValueError, PermissionError, OSError) as exc:
            self.status_var.set(f"⛔ CONTROL INTEGRITY ERROR: {str(exc)[:65]}")
            self.status.configure(fg=RED)
            for var in list(self.feature_vars.values()) + list(self.tool_vars.values()):
                var.set(False)
        if self.root.winfo_exists():
            self.root.after(1700, self.refresh)


def launch(state_dir: Path | None = None, config: Path | None = None, *,
           operator_socket: Path | None = None, direct_state: bool = False,
           topmost: bool = True) -> int:
    import tkinter as tk
    if operator_socket is not None:
        from .broker import OperatorClient
        from types import SimpleNamespace
        state = OperatorClient(operator_socket)
        # Tool names are retrieved from the authenticated broker rather than a
        # local config file which could be edited by the agent.
        policy = SimpleNamespace(tool_pins={name: "" for name in state.status()["tools"]})
    elif direct_state and state_dir is not None and config is not None:
        policy = Policy.from_file(config)
        state = State(state_dir / "audit.sqlite3", get_or_create_key(state_dir / "audit.key"))
    else:
        raise PermissionError("overlay_needs_operator_socket")
    root = tk.Tk()
    OperatorOverlay(root, state, policy, topmost=topmost)
    root.mainloop()
    return 0
