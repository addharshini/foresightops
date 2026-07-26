"""ForesightOps CLI entry point."""

import argparse
import json
import os
import sys
import webbrowser
from pathlib import Path

from . import __version__
from .analyzer import BlastRadiusAnalyzer
from .demo_mode import build_demo_result
from .report import generate_html_report


BANNER = r"""
  ___               _       _     _    ___
 | __| ___ _ _ ___ _(_)__ _| |_  / |  / _ \ _ __  ___
 | _| / _ \ '_/ -_|_) / _` | ' \ | | | (_) | '_ \(_-<
 |_| \___/_| \___(_)_\__, |_||_||_|  \___/| .__//__/
                       |___/               |_|
 CI/CD Blast Radius Analyzer  v{version}
 "Not another scanner — automated remediation before the vulnerability reaches code"
""".format(version=__version__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="foresightops",
        description="ForesightOps — Analyze CI/CD blast radius from a GitHub Actions workflow run",
    )
    parser.add_argument("--version", action="version", version=f"ForesightOps {__version__}")

    sub = parser.add_subparsers(dest="command")

    # analyze command
    analyze = sub.add_parser("analyze", help="Analyze a real GitHub Actions workflow run")
    analyze.add_argument("--owner", required=True, help="GitHub repository owner (org or user)")
    analyze.add_argument("--repo", required=True, help="GitHub repository name")
    analyze.add_argument("--run-id", required=True, type=int, help="Workflow run ID")
    analyze.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"), help="GitHub personal access token (or set GITHUB_TOKEN env var)")
    analyze.add_argument("--output", default="foresightops_report.html", help="Output HTML report path")
    analyze.add_argument("--json", action="store_true", help="Also write a JSON summary")
    analyze.add_argument("--open", action="store_true", dest="open_browser", help="Open report in browser after generation")

    # demo command
    demo = sub.add_parser("demo", help="Generate a demo report (no GitHub token needed)")
    demo.add_argument("--output", default="foresightops_demo_report.html", help="Output HTML report path")
    demo.add_argument("--open", action="store_true", dest="open_browser", help="Open report in browser after generation")

    return parser.parse_args()


def _print_summary(result) -> None:
    color_map = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[33m", "LOW": "\033[92m"}
    reset = "\033[0m"
    bold = "\033[1m"
    risk_color = color_map.get(result.risk_label, "")

    print(f"\n{bold}{'='*60}{reset}")
    print(f"  {bold}Blast Radius Analysis Complete{reset}")
    print(f"{'='*60}")
    print(f"  Repo:         {result.owner}/{result.repo}")
    print(f"  Run ID:       #{result.run_id}")
    print(f"  Workflow:     {result.workflow_name}")
    print(f"  Triggered By: {result.triggered_by}")
    print(f"\n  {bold}Risk Score:{reset}    {risk_color}{bold}{result.risk_score}/100  [{result.risk_label}]{reset}")
    print(f"\n  Findings:")
    crit = sum(1 for f in result.permission_findings if f.risk == "CRITICAL")
    high = sum(1 for f in result.permission_findings if f.risk == "HIGH")
    med  = sum(1 for f in result.permission_findings if f.risk == "MEDIUM")
    print(f"    {color_map['CRITICAL']}CRITICAL{reset}: {crit}   {color_map['HIGH']}HIGH{reset}: {high}   {color_map['MEDIUM']}MEDIUM{reset}: {med}")
    print(f"\n  Secrets in scope: {len(result.exposed_secrets)}")
    print(f"  Lateral movement paths: {len(result.lateral_paths)}")
    if result.has_id_token:
        print(f"\n  {color_map['CRITICAL']}{bold}[!] OIDC id-token enabled -- cloud credential exposure risk!{reset}")
    if result.using_default_permissions:
        print(f"  {color_map['CRITICAL']}{bold}[!] No explicit permissions set -- GitHub defaults are too broad!{reset}")
    print(f"\n{'='*60}\n")


def cmd_analyze(args: argparse.Namespace) -> None:
    if not args.token:
        print("ERROR: GitHub token required. Set --token or GITHUB_TOKEN environment variable.", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing run #{args.run_id} in {args.owner}/{args.repo}...")
    analyzer = BlastRadiusAnalyzer(args.token)
    result = analyzer.analyze(args.owner, args.repo, args.run_id)

    _print_summary(result)

    report_path = generate_html_report(result, args.output)
    print(f"HTML report saved: {report_path}")

    if args.json:
        json_path = Path(args.output).with_suffix(".json")
        data = {
            "owner": result.owner,
            "repo": result.repo,
            "run_id": result.run_id,
            "risk_score": result.risk_score,
            "risk_label": result.risk_label,
            "permissions": result.permissions_used,
            "critical_count": sum(1 for f in result.permission_findings if f.risk == "CRITICAL"),
            "exposed_secrets": [{"name": s.name, "scope": s.scope} for s in result.exposed_secrets],
            "lateral_paths": len(result.lateral_paths),
            "has_id_token": result.has_id_token,
            "using_default_permissions": result.using_default_permissions,
            "analysis_timestamp": result.analysis_timestamp,
        }
        json_path.write_text(json.dumps(data, indent=2))
        print(f"JSON summary saved: {json_path}")

    if args.open_browser:
        webbrowser.open(f"file://{Path(report_path).resolve()}")


def cmd_demo(args: argparse.Namespace) -> None:
    print("Generating demo report (no GitHub token needed)...")
    result = build_demo_result()
    _print_summary(result)
    report_path = generate_html_report(result, args.output)
    print(f"Demo HTML report saved: {report_path}")
    if args.open_browser:
        webbrowser.open(f"file://{Path(report_path).resolve()}")


def main() -> None:
    print(BANNER)
    args = parse_args()

    if args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "demo":
        cmd_demo(args)
    else:
        print("Usage: foresightops [analyze|demo] --help")
        sys.exit(1)


if __name__ == "__main__":
    main()
