import socket

SERVICE_BY_PORT = {
    21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    3306: "MySQL/MariaDB", 5432: "PostgreSQL", 6379: "Redis", 139: "SMB", 445: "SMB",
}

def run(ip, port, **kwargs):
    # Try banner grabbing first
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect((ip, port))

            # Send a basic payload that might trigger a response from HTTP/generic services
            # if they don't send a banner immediately upon connection
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                # Truncate long banners for clean output
                if len(banner) > 50:
                    banner = banner[:47] + "..."
                # Replace newlines
                banner = banner.replace('\r', '').replace('\n', ' ')
                return f"[INFO] Banner grab on {ip}:{port} - {banner}"
    except Exception:
        pass

    # Fallback to dictionary lookup
    service = SERVICE_BY_PORT.get(port)
    if service:
        return f"[INFO] {service} appears open on {ip}:{port}"
    return None
