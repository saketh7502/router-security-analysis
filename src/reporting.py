import json
from typing import Dict, Any, List

def generate_markdown_report(device_info: Dict[str, Any], parsed_data: Dict[str, str], correlated_cves: List[Dict[str, str]], routersploit_output=None) -> str:
    """
    Generates a human-readable Markdown report for a single device.
    """
    report = f"# Security Analysis for IP: {device_info.get('ip_str', 'N/A')}\n\n"
    report += f"**Timestamp:** {device_info.get('timestamp', 'N/A')}\n"
    report += f"**Port:** {device_info.get('port', 'N/A')}\n\n"

    report += "## AI-Extracted Device Details\n"
    report += f"```json\n{json.dumps(parsed_data, indent=2)}\n```\n\n"

    report += "## AI-Correlated Vulnerabilities\n"
    if not correlated_cves:
        report += "No relevant high-impact vulnerabilities were identified by the AI correlator.\n"
    else:
        for cve in correlated_cves:
            report += f"- **{cve.get('cve_id')}**: {cve.get('explanation')}\n"
    
    report += "## Optional Routersploit Scan\n"
    if routersploit_output:
        report += f"```\n{routersploit_output}\n```\n"
    else:
        report += "Routersploit scan was skipped or unavailable.\n"
    
    report += "\n---\n"
    return report