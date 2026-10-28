"""Module orchestration: the passive default, the scope lock and the confirmation gate."""
import traceback
from dataclasses import dataclass
from rich.console import Console
from rich.markup import escape

from atarus_webscan.scope import read_tty_line, resolve_host, safe_text

CONFIRM_WORD = "yes"


def shown(text) -> str:
    """Target-derived text made inert for the terminal.

    Control, format and separator characters become visible escapes
    (safe_text) and rich markup brackets are neutralised (escape), so a
    Location header, a server banner or nuclei's stderr cannot style, clear
    or retitle the operator's terminal.
    """
    return escape(safe_text(text))


@dataclass
class ModuleResult:
    """Result of a module execution"""
    success: bool
    message: str
    error: str = ""


class ModuleRunner:
    """Runs the registered modules in order.

    Modules registered with active=True send more than the safe requests
    (one GET, one HEAD, one OPTIONS) to the named URL. They run only when the
    runner was created with active=True, only when the named host is covered
    by active_scope, and only after the confirmation gate has passed. The
    gate reads the word "yes" from the controlling terminal, or accepts
    assume_yes (the --yes flag), which is recorded in the result. Nothing
    else can open the gate.
    """

    def __init__(self, console: Console, result, client, verbose: bool = False,
                 skip: list = None, only: list = None, active: bool = False,
                 active_scope=None, assume_yes: bool = False):
        self.console = console
        self.result = result
        self.client = client
        self.verbose = verbose
        self.skip = [s.strip().lower() for s in (skip or [])]
        self.only = [s.strip().lower() for s in (only or [])]
        self.active = bool(active)
        self.active_scope = active_scope
        self.assume_yes = bool(assume_yes)
        if self.active and self.active_scope is None:
            raise ValueError("active runs need an active_scope")
        self.result.mode = "active" if self.active else "passive"
        if self.active_scope is not None:
            self.result.active_scope = list(self.active_scope.entries)
        self.modules = []
        self._gate_open = None
        self._gate_reason = ""

    def register(self, name: str, key: str, func, active: bool = False):
        """Register a module. Key is the short name used in --skip/--only.
        active=True marks a module that sends more than the safe requests to the target.
        """
        self.modules.append({"name": name, "key": key, "func": func, "active": bool(active)})

    def _should_run(self, key: str) -> bool:
        if self.only:
            return key in self.only
        if self.skip:
            return key not in self.skip
        return True

    def selected_modules(self) -> list:
        return [m for m in self.modules if self._should_run(m["key"])]

    def _not_run(self, module: dict, reason: str):
        self.result.modules_not_run.append({"module": module["key"], "name": module["name"], "reason": reason})
        self.console.print(f"  [dim]not run[/dim] [cyan]{escape(module['name'])}[/cyan]: {shown(reason)}")

    def _confirm_active(self, active_modules: list) -> bool:
        """The confirmation gate. Runs once, before the first active request.

        Prints the named URL, its resolved addresses, the exact scope, the
        active modules and the paths named for state-changing methods, then
        waits for the word "yes" typed on the terminal. --yes (assume_yes)
        stands in for the typed word on non-interactive runs and is recorded
        in the result. No environment variable or configuration file is read.
        """
        target = self.client.target
        ips = resolve_host(target.host)
        covered = self.active_scope.covers(target.host, ips)

        c = self.console
        c.print("[bold yellow]Active checks requested[/bold yellow]")
        c.print(f"  [bold]Named URL:[/bold] {target.base_url}")
        c.print(f"  [bold]Origin:[/bold] {target.origin} (resolves to {', '.join(ips) if ips else 'nothing'})")
        c.print(f"  [bold]Scope:[/bold] {self.active_scope.describe()}")
        c.print(f"  [bold]Active modules:[/bold] {', '.join(m['key'] for m in active_modules)}")
        if self.result.probe_paths:
            c.print(f"  [bold]Paths for state-changing methods:[/bold] {', '.join(self.result.probe_paths)}")
        else:
            c.print("  [bold]Paths for state-changing methods:[/bold] none named (write_methods will not run)")
        c.print(f"  [bold]TLS verification:[/bold] {'OFF (--insecure)' if self.client.insecure else 'on'}")
        c.print()

        if not ips:
            self.result.out_of_scope = [{"hostname": target.host, "ip": ""}]
            self._gate_reason = "the named host did not resolve, so it cannot be checked against --scope"
            return False
        if not covered:
            self.result.out_of_scope = [{"hostname": target.host, "ip": ip} for ip in ips]
            self._gate_reason = f"the named host {target.host} ({', '.join(ips)}) is outside --scope"
            return False

        if self.assume_yes:
            self.result.confirmation = "--yes flag (no terminal confirmation)"
            c.print("[yellow]Confirmation taken from --yes; recorded in the report.[/yellow]")
            c.print()
            return True

        prompt = (
            f"Type {CONFIRM_WORD} to send active requests to {target.origin} "
            f"(scope: {self.active_scope.describe()}): "
        )
        answer = read_tty_line(prompt)
        if answer is None:
            self._gate_reason = "no terminal to confirm on; pass --yes with --scope for non-interactive runs"
            return False
        if answer.lower() != CONFIRM_WORD:
            self._gate_reason = "confirmation not given on the terminal"
            return False
        self.result.confirmation = "typed yes on the terminal"
        c.print()
        return True

    def run_module(self, name: str, fn, *args, **kwargs) -> ModuleResult:
        """Execute a module function with error handling and progress."""
        with self.console.status(f"[cyan]{escape(name)}[/cyan]"):
            try:
                result = fn(*args, **kwargs)

                if not isinstance(result, ModuleResult):
                    result = ModuleResult(success=True, message="completed")

                if result.success:
                    self.console.print(f"  [green]done[/green] {shown(result.message)}")
                else:
                    self.console.print(f"  [yellow]not run[/yellow] {shown(result.message)}")

                return result
            except Exception as e:
                error_type = type(e).__name__
                error_msg = str(e)
                self.console.print(f"  [red]error[/red] {error_type}: {shown(error_msg)}")

                if self.verbose:
                    self.console.print(f"[red]{escape(traceback.format_exc())}[/red]")

                return ModuleResult(
                    success=False,
                    message=f"failed: {error_type}",
                    error=error_msg,
                )

    def run(self):
        selected = self.selected_modules()
        active_selected = [m for m in selected if m["active"]]

        for module in selected:
            if module["active"]:
                if not self.active:
                    self._not_run(module, "passive mode; add --active and --scope to run it")
                    continue
                if self._gate_open is None:
                    self._gate_open = self._confirm_active(active_selected)
                if not self._gate_open:
                    self._not_run(module, self._gate_reason)
                    continue

            outcome = self.run_module(module["name"], module["func"], self.result, self.client, self.verbose)
            if not outcome.success:
                # The check was not made, or not completed. Say so in the report.
                self.result.modules_not_run.append(
                    {"module": module["key"], "name": module["name"], "reason": outcome.message}
                )

        # A module the user skipped is also a check that was not made; record it
        # so the report cannot read as clean for it.
        for module in self.modules:
            if not self._should_run(module["key"]):
                self.result.modules_not_run.append(
                    {"module": module["key"], "name": module["name"], "reason": "skipped with --skip or --only"}
                )

        self.result.requests_sent = self.client.request_counts()
        self.result.refused_redirects = list(self.client.refused_redirects)
        return self.result
