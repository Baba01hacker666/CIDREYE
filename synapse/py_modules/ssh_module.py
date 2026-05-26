try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False

import concurrent.futures


def _attempt_login(ip, user, pwd):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            ip, 
            port=22, 
            username=user, 
            password=pwd, 
            timeout=3, 
            allow_agent=False, 
            look_for_keys=False
        )
        client.close()
        return True, f"[CRITICAL] Default SSH credentials ({user}:{pwd}) found on {ip}"
    except paramiko.AuthenticationException:
        return False, None
    except Exception:
        return None, None


def run(ip, port, **kwargs):
    if not SSH_AVAILABLE:
        return None
    if port != 22:
        return None

    # Fetch dynamic credentials passed from the runner orchestration
    creds = kwargs.get("credentials", [])
    if not creds:
        return None

    # Thread out the login attempts for performance
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(creds))) as executor:
        futures = [executor.submit(_attempt_login, ip, user, pwd) for user, pwd in creds]
        
        for future in concurrent.futures.as_completed(futures):
            success, result = future.result()
            if success:
                # Return immediately on the first successful hit
                return result
                
    return None