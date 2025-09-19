#!/usr/bin/env python3
import datetime
import fcntl
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.terminal_theme import DIMMED_MONOKAI
from rich.text import Text

TRIVY_NEEDS_DOCKER = False

# Load environment variables
load_dotenv()

# Email configuration
MAIL_TO = "cvanlijnden@gmail.com"
MAIL_FROM = os.environ.get("MAIL_FROM")
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))


@dataclass
class UpdateNotification:
    """Structured update information from Diun environment variables."""

    status: str
    image: str
    hub_link: str
    digest: str
    created: str
    platform: str

    container_id: str | None = None
    container_names: str | None = None
    container_state: str | None = None
    container_status: str | None = None

    @classmethod
    def from_environment(cls) -> "UpdateNotification":
        return cls(
            status=os.environ.get("DIUN_ENTRY_STATUS"),
            image=os.environ.get("DIUN_ENTRY_IMAGE"),
            hub_link=os.environ.get("DIUN_ENTRY_HUBLINK"),
            digest=os.environ.get("DIUN_ENTRY_DIGEST"),
            created=os.environ.get("DIUN_ENTRY_CREATED"),
            platform=os.environ.get("DIUN_ENTRY_PLATFORM"),
            container_id=os.environ.get("DIUN_ENTRY_METADATA_CTN_ID"),
            container_names=os.environ.get("DIUN_ENTRY_METADATA_CTN_NAMES"),
            container_state=os.environ.get("DIUN_ENTRY_METADATA_CTN_STATE"),
            container_status=os.environ.get("DIUN_ENTRY_METADATA_CTN_STATUS"),
        )


@dataclass
class ImageInfo:
    """Information about an image."""

    image: str
    digest: str
    created: str

    @classmethod
    def from_notification(cls, notification: UpdateNotification) -> "ImageInfo":
        return cls(
            image=notification.image,
            digest=notification.digest,
            created=notification.created,
        )


@dataclass
class CVEInfo:
    """Information about a CVE vulnerability - minimal fields for comparison."""

    id: str  # CVE-2023-1234 (for matching)
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    pkg_name: str  # Package name (e.g., "openssl")
    installed_version: str | None = None  # Current vulnerable version
    fixed_version: str | None = None  # Version that fixes it
    title: str | None = None  # Brief description (optional)
    description: str | None = None  # Brief description (optional)


def get_current_container_infos(container_id: str) -> ImageInfo | None:
    cmd = ["docker", "inspect", "--format", "{{.Config.Image}}|{{.Image}}|{{.Created}}", container_id]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    image, digest, created = result.stdout.strip().split("|")
    return ImageInfo(image=image, digest=digest, created=created)


def scan_with_trivy(image: str, image_source: str) -> dict[str, CVEInfo]:
    prefix = ["docker", "compose", "exec", "-T", "trivy"] if TRIVY_NEEDS_DOCKER else []
    cmd = prefix + ["trivy", "image", "--image-src", image_source, "--format", "json", image]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    trivy_data = json.loads(result.stdout.strip())

    cves = {}
    for result in trivy_data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            cve = CVEInfo(
                id=vuln.get("VulnerabilityID", "UNKNOWN"),
                severity=vuln.get("Severity", "UNKNOWN"),
                pkg_name=vuln.get("PkgName", "UNKNOWN"),
                installed_version=vuln.get("InstalledVersion", "UNKNOWN"),
                fixed_version=vuln.get("FixedVersion", "UNKNOWN"),
                title=vuln.get("Title", "UNKNOWN"),
                description=vuln.get("Description", "UNKNOWN"),
            )
            uid = f"{vuln.get('PkgName', 'UNKNOWN')}-{vuln.get('InstalledVersion', 'UNKNOWN')}-{vuln.get('VulnerabilityID', 'UNKNOWN')}"
            cves[uid] = cve
    return cves


def get_severity_color(severity: str) -> str:
    """Return color for severity level."""
    colors = {"CRITICAL": "purple", "HIGH": "red", "MEDIUM": "orange3", "LOW": "yellow"}
    return colors.get(severity, "white")


def get_severity_order(severity: str) -> int:
    """Return sorting order for severity (lower number = higher priority)."""
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return order.get(severity, 99)


def create_comparison_table(
    status: str,
    current_info: ImageInfo,
    update_info: ImageInfo,
    current_cves: dict[str, CVEInfo],
    update_cves: dict[str, CVEInfo],
) -> str:
    from rich.terminal_theme import MONOKAI

    console = Console(record=True, width=120)

    current_text = Text(f"Current Image:", style="magenta") + Text(
        f"{current_info.image} (created at: {current_info.created}, digest: {current_info.digest})", style="white"
    )
    update_text = Text(f"Updated Image:", style="green") + Text(
        f"{update_info.image} (created at: {update_info.created}, digest: {update_info.digest})", style="white"
    )
    intro = (
        "########## UPDATE DETECTED ##########"
        if status == "update"
        else "########## NEW VERSION DETECTED ##########"
        if status == "new"
        else "######UNKNOWN STATUS##########"
    )
    console.print(intro)
    console.print(current_text)
    console.print(update_text)
    console.print()

    # Summary table
    summary_table = Table(title="🔒 Security Vulnerability Comparison Summary", show_header=True)
    summary_table.add_column("Metric", style="cyan", width=20)
    summary_table.add_column("Current Image", style="white", width=15)
    summary_table.add_column("Updated Image", style="white", width=15)
    summary_table.add_column("Change", width=15)

    def count_by_severity(cves_dict):
        counts = {}
        for cve in cves_dict.values():
            counts[cve.severity] = counts.get(cve.severity, 0) + 1
        return counts

    current_counts = count_by_severity(current_cves)
    update_counts = count_by_severity(update_cves)

    # Total CVEs row
    total_change = len(update_cves) - len(current_cves)
    total_change_text = Text(
        f"{total_change:+d}", style="green" if total_change < 0 else "red" if total_change > 0 else "white"
    )
    summary_table.add_row("Total CVEs", str(len(current_cves)), str(len(update_cves)), total_change_text)

    # Severity breakdown rows
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        current = current_counts.get(severity, 0)
        updated = update_counts.get(severity, 0)
        change = updated - current
        change_text = Text(f"{change:+d}", style="green" if change < 0 else "red" if change > 0 else "white")
        summary_table.add_row(f"{severity} CVEs", str(current), str(updated), change_text)

    console.print(summary_table)
    console.print()

    # Tables for new, fixed and common CVEs
    def display_cve_table(uids: set[str], cves: dict[str, CVEInfo], title: str):
        table = Table(title=title, show_header=True)
        table.add_column("CVE ID", style="white", width=15)
        table.add_column("Package", style="white", width=15)
        table.add_column("Severity", width=8)
        table.add_column("Title", style="white", width=22)
        table.add_column("Description", style="white", width=60)

        sorted_uids = sorted(uids, key=lambda uid: (get_severity_order(cves[uid].severity), uid))
        for uid in sorted_uids:
            cve = cves[uid]
            title = cve.title
            severity_text = Text(cve.severity, style=get_severity_color(cve.severity))
            table.add_row(cve.id, cve.pkg_name, severity_text, title, cve.description)
        console.print(table)
        console.print()

    current_uids = set(current_cves.keys())
    update_uids = set(update_cves.keys())

    fixed_cves = current_uids - update_uids
    new_cves = update_uids - current_uids
    common_cves = current_uids & update_uids

    if fixed_cves:
        display_cve_table(fixed_cves, current_cves, "✅ Fixed Vulnerabilities")

    if new_cves:
        display_cve_table(new_cves, update_cves, "⚠️  New Vulnerabilities")

    if common_cves:
        display_cve_table(common_cves, current_cves, "🔄 Unchanged Vulnerabilities")

    # Export HTML with dark theme
    return console.export_html(theme=MONOKAI)


def notify_by_email(html_report: str, subject: str = "Docker Image Update Notification"):
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from smtplib import SMTP

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = MAIL_FROM
    msg["To"] = MAIL_TO

    html_part = MIMEText(html_report, "html")
    msg.attach(html_part)

    # Send email
    with SMTP(MAIL_SERVER, MAIL_PORT) as server:
        server.starttls()  # Enable TLS encryption
        server.login(MAIL_FROM, MAIL_PASSWORD)
        server.send_message(msg)


def main():
    # Serialize script execution to avoid crashes if diun calls our script multiple times in rapid succession
    lock_file_path = Path("reports/script.lock")
    lock_file_path.parent.mkdir(exist_ok=True)

    with open(lock_file_path, "a") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)

        try:
            load_dotenv()

            notification = UpdateNotification.from_environment()
            update_info = ImageInfo.from_notification(notification)
            update_cves = scan_with_trivy(update_info.image, "remote")

            current_info = get_current_container_infos(notification.container_id)
            current_cves = scan_with_trivy(current_info.image, "docker")

            html_report = create_comparison_table(notification.status, current_info, update_info, current_cves, update_cves)
            notify_by_email(html_report)

            # Save HTML report for debugging
            date_time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
            report_file = Path("reports") / f"cve_report_{notification.container_names}_{date_time}.html"
            report_file.parent.mkdir(exist_ok=True)
            report_file.write_text(html_report)

        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


if __name__ == "__main__":
    if not os.environ.get("DIUN_ENTRY_STATUS"):
        # simulate diun notification for testing purposes
        test_env = json.load(open("scripts/logs/test_env.jsonl"))
        os.environ.update(test_env)
    main()
