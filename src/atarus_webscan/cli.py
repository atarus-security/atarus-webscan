"""Command-line interface for atarus-webscan"""
import os
import sys
from datetime import datetime
import click
from rich.console import Console
from rich.table import Table

from atarus_webscan import __version__
from atarus_webscan.models import ScanResult
from atarus_webscan.scope import ScopeValidator, ActiveScope, tty_available
from atarus_webscan.transport import Client
from atarus_webscan.runner import ModuleRunner, shown
from atarus_webscan.modules import discover, headers, methods, dangerous_files, write_methods, technology, risk
from atarus_webscan.reports import html as html_report
from atarus_webscan.reports import json_export
from atarus_webscan.reports import pdf as pdf_report


BANNER = r"""[red]
   ╔═╗╔╦╗╔═╗╦═╗╦ ╦╔═╗  ╦ ╦╔═╗╔╗ ╔═╗╔═╗╔═╗╔╗╔
   ╠═╣ ║ ╠═╣╠╦╝║ ║╚═╗  ║║║║╣ ╠╩╗╚═╗║  ╠═╣║║║
   ╩ ╩ ╩ ╩ ╩╩╚═╚═╝╚═╝  ╚╩╝╚═╝╚═╝╚═╝╚═╝╩ ╩╝╚╝
   Atarus Offensive Security | v{version}[/red]
"""


# (name, key, function, active). A passive module sends at most the safe
# requests (one GET, one HEAD, one OPTIONS) to the URL the user named, or
# works offline. active=True marks a module that sends anything more: it runs
# only behind --active, inside --scope and after the confirmation gate.
MODULE_REGISTRY = [
    ("Site discovery", "discover", discover.run, False),
    ("Security headers", "headers", headers.run, False),
    ("HTTP methods (OPTIONS and HEAD)", "methods", methods.run, False),
    ("Dangerous file detection", "dangerous_files", dangerous_files.run, True),
    ("State-changing HTTP methods", "write_methods", write_methods.run, True),
    ("Technology + CVE scan (nuclei)", "technology", technology.run, True),
    ("Risk scoring", "risk", risk.run, False),
]

ACTIVE_MODULES = [key for _, key, _, active in MODULE_REGISTRY if active]
PASSIVE_MODULES = [key for _, key, _, active in MODULE_REGISTRY if not active]

# Kept for callers of the old name.
MODULE_MAP = {key: (name, func) for name, key, func, _ in MODULE_REGISTRY}


def _parse_probe_path(value: str, target: ScopeValidator) -> str:
    """A --probe-path is an absolute path on the named origin, or a URL on that origin."""
    value = (value or "").strip()
    if not value:
        raise click.UsageError("--probe-path is empty")
    if "://" in value:
        if not target.same_origin(value):
            raise click.UsageError(f"--probe-path {value} is not on the named origin {target.origin}")
        from urllib.parse import urlsplit
        value = urlsplit(value).path or "/"
    if not value.startswith("/"):
        raise click.UsageError(f"--probe-path must start with /: {value}")
    return value


@click.command()
@click.option("-t", "--target", default="", help="Target URL. Scheme, host, port and path are kept exactly as given.")
@click.option("-o", "--output", default="output", help="Output directory")
@click.option("--format", "fmt", default="all", type=click.Choice(["html", "json", "pdf", "all"]))
@click.option("-r", "--rate-limit", default=10, type=int, help="Requests per second (applied to every request this tool sends itself)")
@click.option("--only", help="Comma-separated list of modules to run")
@click.option("--skip", help="Comma-separated list of modules to skip")
@click.option("--active", is_flag=True, help="Run the modules that send more than the safe requests (dangerous_files, write_methods, technology). Needs --scope and a typed confirmation.")
@click.option("--scope", "scope_spec", default="", help="Hosts, networks or domains allowed for active checks: a file with one entry per line, or a comma-separated list (app.example.com, *.example.com, 203.0.113.0/24). Required with --active.")
@click.option("--yes", "assume_yes", is_flag=True, help="Stand in for the typed confirmation on non-interactive runs. Accepted only with --scope; its use is recorded in the report.")
@click.option("--probe-path", "probe_paths", multiple=True, help="Path on the named origin to send the state-changing method probes (POST, PUT, PATCH, DELETE, TRACE, CONNECT) to. Repeatable. Only with --active; without it write_methods does not run.")
@click.option("--insecure", is_flag=True, help="Do not verify the target's TLS certificate. Recorded in the report.")
@click.option("--list-modules", is_flag=True, help="List available modules and exit")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.version_option(__version__)
def main(target, output, fmt, rate_limit, only, skip, active, scope_spec, assume_yes, probe_paths, insecure, list_modules, verbose):
    """atarus-webscan: Web application security scanner

    Passive by default: a plain run sends one GET, one HEAD and one OPTIONS
    to the URL you named and nothing else. Active checks need --active, a
    --scope, and the word yes typed on the terminal (or --yes together with
    --scope for scripted runs).
    """

    console = Console()

    if list_modules:
        table = Table(title="Available modules")
        table.add_column("Key", style="bold cyan")
        table.add_column("Mode")
        table.add_column("Description")
        for name, key, _, is_active in MODULE_REGISTRY:
            table.add_row(key, "active (needs --active)" if is_active else "passive", name)
        console.print(table)
        return

    if not target:
        raise click.UsageError("--target is required. Use -t https://example.com")

    try:
        scope = ScopeValidator(target)
    except ValueError as e:
        raise click.UsageError(f"Invalid target: {e}")

    skip_list = [s.strip() for s in skip.split(",") if s.strip()] if skip else []
    only_list = [s.strip() for s in only.split(",") if s.strip()] if only else []

    # The gate rules. A flag alone never opens it: --yes needs --scope, and
    # --active needs --scope plus either a terminal or --yes. Click reads no
    # environment variables for these options and there is no config file.
    if assume_yes and not scope_spec:
        raise click.UsageError("--yes is only accepted together with --scope")
    if active and not scope_spec:
        raise click.UsageError(
            "--active requires --scope: a file or comma-separated list of the hosts, "
            "networks or domains you are authorized to probe"
        )
    if probe_paths and not active:
        raise click.UsageError("--probe-path is only used with --active; state-changing methods are never sent in a passive run")
    active_scope = None
    if scope_spec:
        try:
            active_scope = ActiveScope.from_option(scope_spec)
        except (ValueError, OSError) as e:
            raise click.UsageError(f"--scope: {e}")
    wanted_active = [k for k in only_list if k.lower() in ACTIVE_MODULES]
    if wanted_active and not active:
        raise click.UsageError(
            f"--only names active modules ({', '.join(wanted_active)}); add --active and --scope to run them"
        )
    if active and not assume_yes and not tty_available():
        raise click.UsageError(
            "--active needs a terminal to type the confirmation on; run interactively, "
            "or pass --yes together with --scope for a non-interactive run"
        )
    probe_list = []
    for p in probe_paths:
        parsed = _parse_probe_path(p, scope)
        if parsed not in probe_list:
            probe_list.append(parsed)

    if insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    output = os.path.abspath(output)
    os.makedirs(output, exist_ok=True)
    os.environ["ATARUS_OUTPUT_DIR"] = output

    console.print(BANNER.format(version=__version__))
    console.print(f"[bold]Target:[/bold] {scope.base_url}")
    if scope.dropped_query:
        console.print("[dim]  query string and fragment are not used[/dim]")
    console.print(f"[bold]Output:[/bold] {output}")
    console.print(f"[bold]Format:[/bold] {fmt}")
    console.print(f"[bold]Rate limit:[/bold] {rate_limit} req/s")
    console.print(f"[bold]Mode:[/bold] {'active' if active else 'passive (one GET, one HEAD, one OPTIONS to the named URL; add --active and --scope to probe)'}")
    console.print(f"[bold]Requests go to:[/bold] {scope.origin} only; redirects elsewhere are refused")
    if active_scope is not None:
        console.print(f"[bold]Scope:[/bold] {active_scope.describe()}")
        if not active:
            console.print("[dim]--scope given without --active: nothing will be probed.[/dim]")
    if assume_yes:
        console.print("[yellow]--yes given: the terminal confirmation will be skipped and this is recorded in the report.[/yellow]")
    if insecure:
        console.print("[yellow]--insecure given: TLS certificate verification is OFF and this is recorded in the report.[/yellow]")
    console.print()

    result = ScanResult(target=scope.target, named_url=scope.base_url, insecure=insecure, probe_paths=probe_list)
    result.started_at = datetime.now().isoformat()

    client = Client(scope, insecure=insecure, rate_limit=rate_limit)
    runner = ModuleRunner(
        console, result, client, verbose=verbose, skip=skip_list, only=only_list,
        active=active, active_scope=active_scope, assume_yes=assume_yes,
    )
    for name, key, fn, is_active in MODULE_REGISTRY:
        runner.register(name, key, fn, active=is_active)

    selected = runner.selected_modules()
    console.print(f"[bold]Modules:[/bold] {len(selected)} selected, {len(MODULE_REGISTRY) - len(selected)} skipped")
    console.print()

    runner.run()

    result.finished_at = datetime.now().isoformat()

    console.print()
    console.print("[bold green]Scan complete[/bold green]")
    console.print(f"  Target: {result.named_url}")
    console.print(f"  Mode: {result.mode}" + (f", confirmation: {result.confirmation or 'not given'}" if result.mode == "active" else ""))
    sent = ", ".join(f"{m} {n}" for m, n in sorted(result.requests_sent.items())) or "none"
    console.print(f"  Requests sent: {sent} (all to {scope.origin})")
    if result.refused_redirects:
        console.print(f"  Redirects refused (off-origin): {len(result.refused_redirects)}")
    if result.insecure:
        console.print("  TLS verification: OFF (--insecure)")
    console.print(f"  Site type: {shown(result.site_type or 'unknown')}")
    console.print(f"  Framework: {shown(result.framework or 'not detected')}")
    console.print(f"  Findings: {len(result.findings)}")
    console.print(f"  Technologies: {len(result.technologies)}")
    console.print(f"  Risk: {result.risk_level or 'unrated'} ({result.risk_score}/100)")
    if result.modules_not_run:
        console.print(f"  Modules not run: {', '.join(m['module'] for m in result.modules_not_run)}")
    console.print(f"  Duration: {result.started_at} to {result.finished_at}\n")

    # Generate reports
    html_path = None

    if fmt in ("html", "all"):
        try:
            html_path = html_report.generate(result, output)
            console.print(f"[bold]HTML report:[/bold] {html_path}")
        except Exception as e:
            console.print(f"[red]HTML report failed: {e}[/red]")

    if fmt in ("json", "all"):
        try:
            json_path = json_export.generate(result, output)
            console.print(f"[bold]JSON report:[/bold] {json_path}")
        except Exception as e:
            console.print(f"[red]JSON report failed: {e}[/red]")

    if fmt in ("pdf", "all"):
        try:
            pdf_path = pdf_report.generate(result, output, existing_html_path=html_path)
            console.print(f"[bold]PDF report:[/bold] {pdf_path}")
        except Exception as e:
            console.print(f"[red]PDF report failed: {e}[/red]")


if __name__ == "__main__":
    main()
