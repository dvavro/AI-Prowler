"""The Estimator's step in Setup AI-Prowler: a short window that turns it on and takes the company basics.

setup_wizard.GUIDED["estimator"] opens it. Everything else (trades, AI agents, Director settings) is on the
🏗 Estimator tab, which "Open this tab" goes to.
"""
from __future__ import annotations

from estimator.ui import model


def make_flow(panel):
    """setup_wizard.GUIDED calls this with the Setup panel. Imported late so setup_wizard never needs the Estimator."""
    import setup_wizard as sw

    class EstimatorFlow(sw._SimpleFlow):
        FIELDS = (("name", "Company name *", 34), ("phone", "Phone", 18), ("tax_pct", "Sales tax %", 8),
                  ("overhead_pct", "Overhead %", 8), ("profit_pct", "Profit %", 8),
                  ("minimum_charge", "Minimum charge $", 8))

        def __init__(self, panel):
            super().__init__(panel, "Estimate and bid jobs", "estimator")
            tk, ttk = self.tk, self.ttk
            self.state = ttk.Label(self.body, text="", font=("Arial", 9, "bold"))
            self.state.pack(anchor="w")
            ttk.Label(self.body, text="Your company basics go on every estimate and bid. Percentages are plain "
                                      "numbers: 8.6 means 8.6%. You can change them any time on the 🏗 Estimator tab.",
                      wraplength=500, justify="left", foreground="#666").pack(anchor="w", pady=(6, 4))
            grid = ttk.Frame(self.body)
            grid.pack(anchor="w")
            try:
                current = model.profile()
            except Exception:  # noqa: BLE001 - a fresh install with no database yet
                current = {}
            self.profile = current
            self.vars = {}
            for i, (key, label, width) in enumerate(self.FIELDS):
                ttk.Label(grid, text=label).grid(row=i, column=0, sticky="w", padx=(0, 8), pady=2)
                var = tk.StringVar(master=self.body, value=current.get(key, ""))
                ttk.Entry(grid, textvariable=var, width=width).grid(row=i, column=1, sticky="w", pady=2)
                self.vars[key] = var
            self._footer("✅ Save", self.save)
            ttk.Button(self._footer_bar, text="⏭ Skip for now", command=self._skip).pack(side="left")
            self._show_state()

        def _show_state(self):
            on = model.is_on()
            self.state.config(text="✅ The Estimator is on" if on else "The Estimator is off: Save turns it on",
                              foreground="#2e7d32" if on else "#b35900")

        def save(self):
            if not model.is_on():
                ok, msg = model.set_on(True)
                if not ok:
                    self._say(msg, False)
                    return
            values = dict(self.profile)
            values.update({k: v.get() for k, v in self.vars.items()})
            ok, msg = model.save_profile(values)
            self._show_state()
            if not ok:
                self._say(msg, False)
                return
            self._say("✅ Saved. Ask your AI \"quote a pressure wash for the Garcia house\" to try it. Trades, AI "
                      "agents and the Director's settings are on the 🏗 Estimator tab.")
            self._done()

        def _skip(self):
            self.panel.progress.set_state(self.module_id, sw.SKIPPED)
            self.panel.render()
            self.win.destroy()

    return EstimatorFlow(panel)
