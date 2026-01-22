"""
CLI Parser for EthiScan.

Provides a rich command-line interface with argparse and rich.
Supports internationalization, crawling, and advanced options.
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from ethiscan import __version__
from ethiscan.core.config import load_config
from ethiscan.core.logger import setup_logger
from ethiscan.scanners.web_scanner import WebScanner


# Rich console for output
console = Console()


def get_disclaimer() -> str:
    """Get translated ethical disclaimer."""
    from ethiscan.core.i18n import t
    
    return f"""
[bold red]⚠️  {t('disclaimer_title')} ⚠️[/bold red]

[yellow]{t('disclaimer_warning')}[/yellow]

By using this tool, you confirm that:
• {t('disclaimer_permission')}
• {t('disclaimer_legal')}
• {t('disclaimer_responsible')}
• {t('disclaimer_no_malicious')}

[red]{t('disclaimer_illegal')}[/red]

{t('disclaimer_liability')}
"""


def print_banner() -> None:
    """Print the EthiScan banner."""
    banner = """
   ███████╗████████╗██╗  ██╗██╗███████╗ ██████╗ █████╗ ███╗   ██╗
   ██╔════╝╚══██╔══╝██║  ██║██║██╔════╝██╔════╝██╔══██╗████╗  ██║
   █████╗     ██║   ███████║██║███████╗██║     ███████║██╔██╗ ██║
   ██╔══╝     ██║   ██╔══██║██║╚════██║██║     ██╔══██║██║╚██╗██║
   ███████╗   ██║   ██║  ██║██║███████║╚██████╗██║  ██║██║ ╚████║
   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    """
    console.print(Text(banner, style="bold cyan"))
    console.print(f"  [dim]Ethical Web Vulnerability Scanner v{__version__}[/dim]\n")


def print_disclaimer() -> None:
    """Print the ethical use disclaimer."""
    console.print(Panel(get_disclaimer(), title="[bold]IMPORTANT[/bold]", border_style="red"))


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="ethiscan",
        description="EthiScan - Ethical Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ethiscan scan --url https://example.com
  ethiscan scan --url https://example.com --format html --crawl-depth 1
  ethiscan scan --url https://example.com --severity MEDIUM --cookie "session=abc123"
  ethiscan scan --url https://example.com --active
  ethiscan list-modules
  ethiscan headers --url https://example.com

Use responsibly. Only scan systems you have permission to test.
        """,
    )
    
    parser.add_argument("-v", "--version", action="version", version=f"EthiScan v{__version__}")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode - minimal output")
    parser.add_argument("--no-banner", action="store_true", help="Don't show banner")
    parser.add_argument("--lang", choices=["en", "pt-br"], default=None, help="Language: en or pt-br")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a target URL for vulnerabilities")
    scan_parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    scan_parser.add_argument("-o", "--output", default="report", help="Output file name (without extension)")
    scan_parser.add_argument("-f", "--format", choices=["txt", "json", "html", "pdf", "all"], default="txt", help="Report format")
    scan_parser.add_argument("--active", action="store_true", help="Enable active scanning (XSS, SQLi)")
    scan_parser.add_argument("-c", "--config", help="Path to custom config file")
    scan_parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    scan_parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification")
    scan_parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompts")
    
    # New v2.0 options
    scan_parser.add_argument("--severity", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                            help="Only show vulnerabilities at or above this severity")
    scan_parser.add_argument("--crawl-depth", type=int, default=0, choices=[0, 1, 2, 3],
                            help="Crawl depth (0=single page, 1-3=follow links)")
    scan_parser.add_argument("--max-pages", type=int, default=20, help="Maximum pages to crawl")
    scan_parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests (seconds)")
    scan_parser.add_argument("--cookie", action="append", help="Cookie in 'name=value' format (can repeat)")
    scan_parser.add_argument("--header", action="append", help="Custom header in 'Name: Value' format (can repeat)")
    scan_parser.add_argument("--log-file", help="Save logs to file")
    
    # List modules command
    subparsers.add_parser("list-modules", help="List all available scanning modules")
    
    # Headers command (debug)
    headers_parser = subparsers.add_parser("headers", help="Show all headers from a URL")
    headers_parser.add_argument("-u", "--url", required=True, help="Target URL")
    
    return parser


def parse_cookies(cookie_args: Optional[List[str]]) -> Dict[str, str]:
    """Parse cookie arguments into a dictionary."""
    cookies = {}
    if cookie_args:
        for cookie in cookie_args:
            if "=" in cookie:
                name, value = cookie.split("=", 1)
                cookies[name.strip()] = value.strip()
    return cookies


def parse_headers(header_args: Optional[List[str]]) -> Dict[str, str]:
    """Parse header arguments into a dictionary."""
    headers = {}
    if header_args:
        for header in header_args:
            if ":" in header:
                name, value = header.split(":", 1)
                headers[name.strip()] = value.strip()
    return headers


def cmd_headers(args: argparse.Namespace) -> None:
    """Execute the headers command."""
    import requests
    from ethiscan.core.utils import create_session
    
    session = create_session()
    
    try:
        response = session.get(args.url, timeout=10)
        
        table = Table(title=f"Headers for {args.url}", show_header=True)
        table.add_column("Header", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        for name, value in sorted(response.headers.items()):
            table.add_row(name, value[:80] + "..." if len(value) > 80 else value)
        
        console.print(table)
        console.print(f"\n[dim]Status: {response.status_code}[/dim]")
        
    except requests.RequestException as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


def cmd_list_modules() -> None:
    """Execute the list-modules command."""
    from ethiscan.core.i18n import t
    
    scanner = WebScanner(active_mode=True)
    modules = scanner.list_modules()
    
    table = Table(title=t("available_modules"), show_header=True)
    table.add_column(t("module"), style="cyan", no_wrap=True)
    table.add_column(t("type"), style="yellow")
    table.add_column(t("description"), style="white")
    
    for name, info in sorted(modules.items()):
        type_style = "red" if info["type"] == "ACTIVE" else "green"
        type_label = t("active") if info["type"] == "ACTIVE" else t("passive")
        table.add_row(name, f"[{type_style}]{type_label}[/{type_style}]", info["description"])
    
    console.print(table)
    console.print(f"\n[dim]{t('passive_note')}[/dim]")
    console.print(f"[dim]{t('active_note')}[/dim]")


def cmd_scan(args: argparse.Namespace) -> None:
    """Execute the scan command."""
    from ethiscan.core.i18n import t
    from ethiscan.core.crawler import Crawler
    from ethiscan.core.utils import create_session
    from ethiscan.core.scoring import calculate_security_score
    
    # Load configuration
    config = load_config(args.config)
    
    # Apply CLI overrides
    if args.timeout:
        config.scanner.timeout = args.timeout
    if args.no_verify_ssl:
        config.scanner.verify_ssl = False
    
    # Setup logging to file if specified
    if args.log_file:
        setup_logger(log_file=args.log_file)
    
    # Active scan confirmation
    if args.active and not args.yes:
        console.print()
        console.print(f"[bold yellow]⚠️  {t('active_scan_warning')}[/bold yellow]")
        console.print()
        console.print(t("active_scan_info"))
        console.print(t("active_scan_alert"))
        console.print()
        
        if not Confirm.ask(f"[yellow]{t('active_scan_confirm')}[/yellow]"):
            console.print(f"[red]{t('scan_cancelled')}[/red]")
            sys.exit(0)
    
    # Parse custom cookies and headers
    custom_cookies = parse_cookies(args.cookie)
    custom_headers = parse_headers(args.header)
    
    # Create session with custom options
    session = create_session(config, custom_headers)
    if custom_cookies:
        session.cookies.update(custom_cookies)
    
    # Create scanner
    scanner = WebScanner(config=config, active_mode=args.active)
    
    # Print scan info
    console.print()
    scan_type_label = t("active") if args.active else t("passive")
    console.print(f"[bold]{t('target')}:[/bold] {args.url}")
    console.print(f"[bold]{t('scan_type')}:[/bold] {'[red]' if args.active else '[green]'}{scan_type_label}[/]")
    console.print(f"[bold]{t('modules')}:[/bold] {', '.join(scanner.modules.keys())}")
    if args.crawl_depth > 0:
        console.print(f"[bold]Crawl Depth:[/bold] {args.crawl_depth} (max {args.max_pages} pages)")
    console.print()
    
    # Crawl if depth > 0
    urls_to_scan = [args.url]
    if args.crawl_depth > 0:
        console.print("[bold cyan]Crawling pages...[/bold cyan]")
        
        crawler = Crawler(
            max_depth=args.crawl_depth,
            max_pages=args.max_pages,
            delay=args.delay
        )
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Discovering pages...", total=args.max_pages)
            
            def progress_callback(current, total, url):
                progress.update(task, completed=current, description=f"Found: {url[:50]}...")
            
            urls_to_scan = crawler.crawl(args.url, session, progress_callback)
            progress.update(task, completed=len(urls_to_scan))
        
        console.print(f"[green]✓[/green] Found {len(urls_to_scan)} page(s) to scan\n")
    
    # Run scans with progress
    all_vulnerabilities = []
    all_headers = {}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("Scanning...", total=len(urls_to_scan))
        
        for url in urls_to_scan:
            progress.update(task, description=f"Scanning {url[:40]}...")
            
            try:
                result = scanner.scan(url, custom_headers)
                all_vulnerabilities.extend(result.vulnerabilities)
                
                # Store headers from first response for scoring
                if not all_headers and hasattr(result, '_headers'):
                    all_headers = result._headers
            except Exception as e:
                console.print(f"[red]Error scanning {url}:[/red] {e}")
            
            progress.advance(task)
    
    # Create combined result
    combined_result = result  # Use last result as base
    combined_result.vulnerabilities = all_vulnerabilities
    
    # Filter by severity if specified
    if args.severity:
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        min_index = severity_order.index(args.severity)
        combined_result.vulnerabilities = [
            v for v in combined_result.vulnerabilities
            if severity_order.index(v.severity) >= min_index
        ]
    
    # Print summary
    console.print()
    print_summary(combined_result, all_headers)
    
    # Generate reports
    generate_reports(combined_result, args.output, args.format)


def print_summary(result, headers: dict = None) -> None:
    """Print scan result summary with security score."""
    from ethiscan.core.i18n import t
    from ethiscan.core.scoring import calculate_security_score
    
    # Calculate score
    score_data = calculate_security_score(result, headers or {})
    
    # Security Score panel
    grade_color = {
        "A+": "green", "A": "green", "B+": "green", "B": "yellow",
        "C": "yellow", "D": "orange1", "F": "red"
    }.get(score_data["grade"], "white")
    
    console.print(Panel(
        f"[bold {grade_color}]{score_data['score']}/100 ({score_data['grade']})[/bold {grade_color}] - {score_data['grade_label']}",
        title="[bold]Security Score[/bold]",
        border_style=grade_color
    ))
    
    # Summary table
    table = Table(title=t("scan_summary"), show_header=True)
    table.add_column(t("metric"), style="cyan")
    table.add_column(t("value"), style="white")
    
    table.add_row(t("target"), result.target.url)
    table.add_row(t("duration"), f"{result.duration:.2f}s")
    table.add_row(t("total_findings"), str(result.vulnerability_count))
    table.add_row(f"[red]{t('critical')}[/red]", str(result.critical_count))
    table.add_row(f"[orange1]{t('high')}[/orange1]", str(result.high_count))
    table.add_row(f"[yellow]{t('medium')}[/yellow]", str(result.medium_count))
    table.add_row(f"[green]{t('low')}[/green]", str(result.low_count))
    table.add_row(f"[blue]{t('info')}[/blue]", str(result.info_count))
    
    console.print(table)
    
    # Vulnerability details
    if result.vulnerabilities:
        console.print()
        vuln_table = Table(title=t("vulnerabilities_found"), show_header=True)
        vuln_table.add_column(t("severity"), width=10)
        vuln_table.add_column(t("name"), style="white")
        vuln_table.add_column(t("module"), style="dim")
        
        severity_styles = {
            "CRITICAL": "red bold", "HIGH": "orange1",
            "MEDIUM": "yellow", "LOW": "green", "INFO": "blue",
        }
        
        for vuln in sorted(result.vulnerabilities, 
                         key=lambda v: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(v.severity)):
            style = severity_styles.get(vuln.severity, "white")
            vuln_table.add_row(
                f"[{style}]{vuln.severity}[/{style}]",
                vuln.name[:50] + "..." if len(vuln.name) > 50 else vuln.name,
                vuln.module,
            )
        
        console.print(vuln_table)


def generate_reports(result, output_name: str, format_type: str) -> None:
    """Generate reports in specified formats."""
    from ethiscan.reporters import txt, json as json_reporter, html, pdf
    from ethiscan.core.i18n import t
    
    reporters = {
        "txt": txt.TxtReporter,
        "json": json_reporter.JsonReporter,
        "html": html.HtmlReporter,
        "pdf": pdf.PdfReporter,
    }
    
    formats = [format_type] if format_type != "all" else ["txt", "json", "html", "pdf"]
    
    console.print()
    for fmt in formats:
        try:
            reporter = reporters[fmt]()
            output_file = reporter.generate(result, output_name)
            console.print(f"[green]✓[/green] {t('report_generated')}: {output_file}")
        except Exception as e:
            console.print(f"[red]✗[/red] {t('report_failed')} {fmt}: {e}")


def main() -> None:
    """Main entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    log_level = "WARNING" if args.quiet else "INFO"
    log_file = getattr(args, 'log_file', None)
    if log_file:
        setup_logger(level=log_level, log_file=log_file)
    else:
        setup_logger(level=log_level)
    
    # Set language
    if args.lang:
        from ethiscan.core.i18n import set_language
        set_language(args.lang)
    else:
        load_config()
    
    # Print banner
    if not args.no_banner and not args.quiet:
        print_banner()
        print_disclaimer()
    
    # Handle commands
    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "list-modules":
        cmd_list_modules()
    elif args.command == "headers":
        cmd_headers(args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
