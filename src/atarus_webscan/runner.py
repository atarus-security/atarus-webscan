"""Module orchestration with progress reporting"""
import traceback
from dataclasses import dataclass
from rich.console import Console


@dataclass
class ModuleResult:
    """Result of a module execution"""
    success: bool
    message: str
    error: str = ""


class ModuleRunner:
    """Runs modules sequentially with rich progress output"""

    def __init__(self, console: Console, verbose: bool = False):
        self.console = console
        self.verbose = verbose

    def run_module(self, name: str, fn, *args, **kwargs) -> ModuleResult:
        """Execute a module function with error handling and progress."""
        with self.console.status(f"[cyan]{name}[/cyan]"):
            try:
                result = fn(*args, **kwargs)

                if not isinstance(result, ModuleResult):
                    result = ModuleResult(success=True, message="completed")

                if result.success:
                    self.console.print(f"  [green]done[/green] {result.message}")
                else:
                    self.console.print(f"  [yellow]warn[/yellow] {result.message}")

                return result
            except Exception as e:
                error_type = type(e).__name__
                error_msg = str(e)
                self.console.print(f"  [red]error[/red] {error_type}: {error_msg}")

                if self.verbose:
                    self.console.print(f"[red]{traceback.format_exc()}[/red]")

                return ModuleResult(
                    success=False,
                    message=f"failed: {error_type}",
                    error=error_msg,
                )
