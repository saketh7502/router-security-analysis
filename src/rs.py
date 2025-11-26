import subprocess
import logging

def is_routersploit_installed() -> bool:
    """
    Checks whether Routersploit is installed.
    """
    try:
        subprocess.run(["rsf.py", "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        logging.warning("Routersploit not found. Skipping optional exploitation phase.")
        return False


def run_routersploit_scan(target_ip: str) -> str:
    """
    Runs a SAFE Routersploit scanner module on the target.
    Only passive checks. No exploitation.
    """
    try:
        cmd = f"""echo -e "use scanners/autopwn\nset target {target_ip}\nrun\nexit" | rsf.py"""
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return output.decode()
    except Exception as e:
        logging.error(f"Routersploit scan failed: {e}")
        return "Routersploit scan failed or returned no output."

def has_module_for_cve(cve_id: str) -> bool:
    """
    Checks if Routersploit has a module for the given CVE ID.
    The search is a simple `rsf.py -m` lookup which returns an error
    if the module does not exist.
    """
    try:
        module_name = cve_id.lower().replace("-", "_")
        cmd = f"rsf.py -m {module_name}"
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()

        if "error" in output.lower() or "not found" in output.lower():
            return False

        return True
    except Exception as e:
        logging.error(f"Module scan failed for {cve_id}: {e}")
        return False