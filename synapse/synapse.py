import argparse
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request

from modules import run_modules

DEFAULT_OUTPUT_FILE = "synapse_results.jsonl"
DEFAULT_COMMON_PORTS = (
    "21,22,80,443,3306,5432,6379,139,445,8080,8443"
)
HTTP_PORTS = {80,443,8080,8443}


def load_env_file(env_path: str = ".env") -> None:
    if not os.path.exists(env_path):
        return

    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError as exc:
        print(f"[-] Failed to read {env_path}: {exc}")


def send_telegram(token, chat_id, text):
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode("utf-8")
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status == 200
    except Exception as e:
        print(f"[-] Telegram error: {e}")
        return False


def _has_http_ports(ports: str) -> bool:
    for part in ports.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start_i, end_i = int(start), int(end)
            except ValueError:
                continue
            for p in HTTP_PORTS:
                if start_i <= p <= end_i:
                    return True
        else:
            try:
                if int(part) in HTTP_PORTS:
                    return True
            except ValueError:
                continue
    return False


def run_synapse(binary_path, target, ports, output_file=DEFAULT_OUTPUT_FILE, extra_args=None):
    cmd = [binary_path, "-t", target, "-p", ports, "-o", output_file, "--json", "--quiet"]
    if extra_args:
        cmd.extend(extra_args)

    if _has_http_ports(ports) and not any(arg.startswith("--nuclei-tags") for arg in (extra_args or [])):
        cmd.extend(["--nuclei-tags", "cve"])

    if os.path.exists(output_file):
        os.remove(output_file)

    print(f"[*] Running SYNapse: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode not in (0, 1):
        print(f"[-] SYNapse failed: {result.stderr}")

    results = []
    if os.path.exists(output_file):
        with open(output_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return results


def main():
    load_env_file()

    parser = argparse.ArgumentParser(description="SYNapse Python Wrapper")
    parser.add_argument("-t", "--target", required=True, help="Target IP or CIDR")
    parser.add_argument(
        "-p",
        "--ports",
        default=DEFAULT_COMMON_PORTS,
        help=f"Ports to scan (default: common services: {DEFAULT_COMMON_PORTS})",
    )
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT_FILE, help="Output JSONL file")
    parser.add_argument("--telegram-token", help="Telegram Bot Token (or TELEGRAM_BOT_TOKEN in .env)")
    parser.add_argument("--telegram-chat", help="Telegram Chat ID (or TELEGRAM_CHAT_ID in .env)")
    parser.add_argument("--no-ftp-module", action="store_true", help="Disable FTP checks")
    parser.add_argument("--no-smb-module", action="store_true", help="Disable SMB checks")
    parser.add_argument("--no-ssh-module", action="store_true", help="Disable SSH default credential checks")
    parser.add_argument("--detect-services", action="store_true", help="Report common services by open default ports")

    args, extra = parser.parse_known_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    binary_path = os.path.join(script_dir, "synapse")

    if not os.path.isfile(binary_path) or not os.access(binary_path, os.X_OK):
        print("[-] SYNapse binary not found or not executable. Please compile it first.")
        sys.exit(1)

    results = run_synapse(binary_path, args.target, args.ports, args.output, extra)
    print(f"[*] Found {len(results)} open ports.")

    for res in results:
        print(f"  - {res.get('ip')}:{res.get('port')} (State: {res.get('state')})")

    print("[*] Running post-scan modules...")
    findings = run_modules(
        results,
        enable_ftp=not args.no_ftp_module,
        enable_smb=not args.no_smb_module,
        enable_ssh=not args.no_ssh_module,
        detect_services=args.detect_services,
    )

    token = args.telegram_token or os.getenv("TELEGRAM_BOT_TOKEN")
    chat = args.telegram_chat or os.getenv("TELEGRAM_CHAT_ID")

    if findings and token and chat:
        print("[*] Sending high/critical findings to Telegram...")
        msg = "SYNapse Module Findings:\n" + "\n".join(findings)
        send_telegram(token, chat, msg)


if __name__ == "__main__":
    main()
