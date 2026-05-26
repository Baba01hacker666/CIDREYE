try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False

import concurrent.futures

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("root", "admin"),
    ("ubnt", "ubnt"),
]

def _attempt_login(ip, user, pwd):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=22, username=user, password=pwd, timeout=3, allow_agent=False, look_for_keys=False)
        client.close()
        return True, f"[CRITICAL] Default SSH credentials ({user}:{pwd}) found on {ip}"
    except paramiko.AuthenticationException:
        return False, None
    except Exception:
        return None, None

def run(ip, port):
    if not SSH_AVAILABLE:
        return None
    if port != 22:
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(DEFAULT_CREDS)) as executor:
        futures = [executor.submit(_attempt_login, ip, user, pwd) for user, pwd in DEFAULT_CREDS]

        for future in concurrent.futures.as_completed(futures):
            success, result = future.result()
            if success:
                return result

    return None
