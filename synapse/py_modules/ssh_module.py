try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False


def run(ip, port, **kwargs):
    if not SSH_AVAILABLE:
        return None
    if port != 22:
        return None

    creds = kwargs.get("credentials", [])
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
