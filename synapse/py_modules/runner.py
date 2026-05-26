"""Module execution orchestration for scan findings."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from . import (
    ftp_module,
    http_module,
    mysql_module,
    postgres_module,
    redis_module,
    service_detect_module,
    smb_module,
    ssh_module,
)

MODULE_REGISTRY = {
    "ftp": ftp_module,
    "smb": smb_module,
    "ssh": ssh_module,
    "service_detect": service_detect_module,
    "redis": redis_module,
    "mysql": mysql_module,
    "postgres": postgres_module,
    "http": http_module,
}

def run_modules(results, enabled_modules, module_configs=None):
    if module_configs is None:
        module_configs = {}

    """Run all enabled modules for each result row.

    Any module failure is isolated so one faulty module does not stop scanning.
    """
    
    findings = []
    active_modules = [
        (name, MODULE_REGISTRY[name])
        for name, enabled in enabled_modules.items()
        if enabled and name in MODULE_REGISTRY
    ]

    # Calculate workers dynamically based on workload size up to a max of 32
    max_workers = min(32, (len(results) * len(active_modules)) or 1)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Map the future object to its specific context (module, ip, port)
        future_to_context = {}
        
        for res in results:
            ip = res.get("ip")
            port = res.get("port")
            if not ip or port is None:
                continue
            for name, module in active_modules:
                # Retrieve configuration specific to this module (e.g., credentials)
                config = module_configs.get(name) or {}
                # Submit thread with kwargs unpacking
                future = executor.submit(module.run, ip, port, **config)
                future_to_context[future] = (module, ip, port)

        # Process results as they complete
        for future in as_completed(future_to_context):
            module, ip, port = future_to_context[future]
            try:
                finding = future.result()
                if finding:
                    findings.append(finding)
                    print(finding)
            except Exception as e:
                module_name = getattr(module, "__name__", "unknown")
                print(f"[-] Module {module_name} error on {ip}:{port}: {e}")

    return findings