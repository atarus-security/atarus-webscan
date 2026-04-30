"""Command-line interface for atarus-webscan"""
import os
import sys
import urllib3
from datetime import datetime
import click
from rich.console import Console

from atarus_webscan import __version__
from atarus_webscan.models import ScanResult
from atarus_webscan.scope import ScopeValidator
from atarus_webscan.baseline import BaselineDetector
from atarus_webscan.runner import ModuleRunner
from atarus_webscan.modules import discover, headers, methods, dangerous_files, technology, risk
from atarus_webscan.reports import html as html_report
from atarus_webscan.reports import json_export
from atarus_webscan.reports import pdf as pdf_report


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


BANNER = r"""[red]
   ╔═╗╔╦╗╔═╗╦═╗╦ ╦╔═╗  ╦ ╦╔═╗╔╗ ╔═╗╔═╗╔═╗╔╗╔
   ╠═╣ ║ ╠═╣╠╦╝║ ║╚═╗  ║║║║╣ ╠╩╗╚═╗║  ╠═╣║║║
   ╩ ╩ ╩ ╩ ╩╩╚═╚═╝╚═╝  ╚╩╝╚═╝╚═╝╚═╝╚═╝╩ ╩╝╚╝
   Atarus Offensive Security | v{version}[/red]
"""


MODULE_MAP = {
    "discover": ("Site discovery", discover.run),
    "headers": ("Security headers", headers.run),
    "methods": ("HTTP methods", methods.run),
    "dangerous_files": ("Dangerous file detection", dangerous_files.run),
    "technology": ("Technology + CVE scan", technology.run),
    "risk": ("Risk scoring", risk.run),
}


@click.command()
@click.option("-t", "--target", required=True, help="Target URL")
@click.option("-o", "--output", default="output", help="Output directory")
@click.option("--format", "fmt", default="all", type=click.Choice(["html", "json", "pdf", "all"]))
@click.option("-r", "--rate-limit", default=10, type=int, help="Requests per second")
@click.option("--only", help="Comma-separated list of modules to run")
@click.option("--skip", help="Comma-separated list of modules to skip")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.version_option(__version__)
def main(target, output, fmt, rate_limit, only, skip, verbose):
    """atarus-webscan: Web application security scanner"""

    console = Console()
    console.print(BANNER.format(version=__version__))

    try:
        scope = ScopeValidator(target)
    except ValueError as e:
        console.print(f"[red]Invalid target: {e}[/red]")
        sys.exit(1)

    base_url = scope.normalize_target()

    output = os.path.abspath(output)
    os.makedirs(output, exist_ok=True)
    os.environ["ATARUS_OUTPUT_DIR"] = output

    console.print(f"[bold]Target:[/bold] {base_url}")
    console.print(f"[bold]Output:[/bold] {output}")
    console.print(f"[bold]Format:[/bold] {fmt}")
    console.print(f"[bold]Rate limit:[/bold] {rate_limit} req/s\n")
    console.print(f"[bold]Scope locked:[/bold] *.{scope.target}\n")

    all_modules = list(MODULE_MAP.keys())
    active = list(all_modules)
    if only:
        only_set = {m.strip() for m in only.split(",")}
        active = [m for m in all_modules if m in only_set]
    if skip:
        skip_set = {m.strip() for m in skip.split(",")}
        active = [m for m in active if m not in skip_set]

    skipped = [m for m in all_modules if m not in active]
    console.print(f"[bold]Modules:[/bold] {len(active)} active, {len(skipped)} skipped")
    if skipped:
        console.print(f"  [dim]Skipped: {', '.join(skipped)}[/dim]")
    console.print()

    result = ScanResult(target=scope.target)
    result.started_at = datetime.now().isoformat()

    baseline = BaselineDetector(base_url)
    if verbose:
        console.print("[dim]  calibrating 404 baseline...[/dim]")
    baseline.calibrate(verbose=verbose)
    result.baseline_404_hash = baseline.baseline_hash[:16] if baseline.baseline_hash else ""
    result.baseline_404_status = baseline.baseline_status

    if verbose and baseline.baseline_hash:
        console.print(f"[dim]  baseline: HTTP {baseline.baseline_status}, hash {baseline.baseline_hash[:16]}, {baseline.baseline_length} bytes[/dim]\n")

    runner = ModuleRunner(console, verbose=verbose)

    for module_name in active:
        label, fn = MODULE_MAP[module_name]
        runner.run_module(label, fn, result, base_url, verbose)

    result.finished_at = datetime.now().isoformat()

    console.print()
    console.print("[bold green]Scan complete[/bold green]")
    console.print(f"  Target: {result.target}")
    console.print(f"  Site type: {result.site_type or 'unknown'}")
    console.print(f"  Framework: {result.framework or 'not detected'}")
    console.print(f"  Findings: {len(result.findings)}")
    console.print(f"  Technologies: {len(result.technologies)}")
    console.print(f"  Risk: {result.risk_level or 'unrated'} ({result.risk_score}/100)")
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
