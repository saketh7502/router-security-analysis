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
