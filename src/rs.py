import subprocess
import logging
import os
import re
import subprocess
import logging
from src.config import ROUTERSPLOIT_MODULE_PATH

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

def product_to_prefix(product: str) -> str:
    """
    Converts product like 'DCS-5020L' → 'dcs_5020l'
    """
    if not product:
        return ""
    return re.sub(r'[^a-zA-Z0-9]', '_', product).lower()


def find_modules_by_product(vendor: str, product: str):
    """
    Searches exploit modules under routersploit for prefix matches.
    Example: product DCS-5020L → prefix 'dcs'
    Matches: dcs_930l_auth_rce.py, dcs_930l_info_disclosure.py
    """
    if not vendor or not product:
        return []

    vendor = vendor.lower()
    prefix = product_to_prefix(product)

    vendor_path = os.path.join(ROUTERSPLOIT_MODULE_PATH, vendor)
    if not os.path.isdir(vendor_path):
        return []

    matched = []
    # match only first 3 characters (e.g., "dcs", "dir", "dsl", etc.)
    prefix_short = prefix[:3]

    for file in os.listdir(vendor_path):
        if file.endswith(".py") and file != "__init__.py":
            module_name = file.replace(".py", "")
            if module_name.startswith(prefix_short):
                matched.append(module_name)

    return matched


def run_specific_module(module_name: str, vendor: str, target_ip: str) -> str:
    """
    Runs a specific Routersploit exploit module:
    Example: vendor = 'dlink', module_name = 'dcs_930l_auth_rce'
    """
    try:
        full_module_path = f"exploits/routers/{vendor.lower()}/{module_name}"
        cmd = (
            f"""echo -e "use {full_module_path}\nset target {target_ip}\nrun\nexit" | rsf.py"""
        )
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return output.decode()

    except Exception as e:
        logging.error(f"Routersploit module failed ({module_name}): {e}")
        return f"Routersploit module '{module_name}' failed or returned no output."