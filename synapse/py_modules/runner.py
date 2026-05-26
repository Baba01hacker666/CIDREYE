"""Module execution orchestration for scan findings."""

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

    for res in results:
        ip = res.get("ip")
        port = res.get("port")
        if not ip or port is None:
            continue
        for name, module in active_modules:
            try:
                finding = module.run(ip, port, **(module_configs.get(name) or {}))
            except Exception:
                continue
            if finding:
                findings.append(finding)
                print(finding)
    return findings
