import ftplib
import paramiko
import smbclient

SERVICE_BY_PORT = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    6379: "Redis",
    139: "SMB",
    445: "SMB",
}


def check_ftp_anonymous(ip):
    try:
        ftp = ftplib.FTP(ip, timeout=5)
        ftp.login()
        ftp.quit()
        return f"[CRITICAL] Anonymous FTP access allowed on {ip}"
    except Exception:
        return None


def check_smb_anonymous(ip):
    try:
        smbclient.ClientConfig(username="guest", password="")
        shares = smbclient.list_shares(ip, port=445, timeout=5)
        if shares:
            return f"[HIGH] Anonymous SMB shares found on {ip}: {', '.join([s.name for s in shares])}"
    except Exception:
        pass

    try:
        smbclient.ClientConfig(username="guest", password="")
        shares = smbclient.list_shares(ip, port=139, timeout=5)
        if shares:
            return f"[HIGH] Anonymous SMB shares found on {ip}: {', '.join([s.name for s in shares])}"
    except Exception:
        pass

    return None


def check_ssh_default_creds(ip):
    creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("root", "admin"),
        ("ubnt", "ubnt"),
    ]

    for user, pwd in creds:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=22, username=user, password=pwd, timeout=3, allow_agent=False, look_for_keys=False)
            client.close()
            return f"[CRITICAL] Default SSH credentials ({user}:{pwd}) found on {ip}"
        except paramiko.AuthenticationException:
            pass
        except Exception:
            break

    return None


def service_finding(ip: str, port: int):
    service = SERVICE_BY_PORT.get(port)
    if service:
        return f"[INFO] {service} appears open on {ip}:{port}"
    return None


def run_modules(results, enable_ftp=True, enable_smb=True, enable_ssh=True, detect_services=False):
    findings = []

    for res in results:
        ip = res.get("ip")
        port = res.get("port")

        if detect_services:
            finding = service_finding(ip, port)
            if finding:
                findings.append(finding)
                print(finding)

        if enable_ftp and port == 21:
            print(f"[*] Checking FTP on {ip}...")
            finding = check_ftp_anonymous(ip)
            if finding:
                findings.append(finding)
                print(finding)

        elif enable_smb and port in (139, 445):
            print(f"[*] Checking SMB on {ip}...")
            finding = check_smb_anonymous(ip)
            if finding:
                findings.append(finding)
                print(finding)

        elif enable_ssh and port == 22:
            print(f"[*] Checking SSH on {ip}...")
            finding = check_ssh_default_creds(ip)
            if finding:
                findings.append(finding)
                print(finding)

    return findings
