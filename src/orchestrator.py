import argparse
import logging
import sys

from concurrent.futures import ThreadPoolExecutor, as_completed
from src.config import SHODAN_API_KEY
from src.api_clients import ( # This import is now correct
    fetch_shodan_data,
    parse_banner_with_llm,
    query_cve_search,
    correlate_cves_with_llm
)
from src.reporting import generate_markdown_report
from src.rs import is_routersploit_installed, run_routersploit_scan, has_module_for_cve

def process_device(device: dict) -> str:
    """
    Runs the full analysis pipeline for a single device.
    """
    structured_data = parse_banner_with_llm(device)
    if not structured_data:
        # Logged inside the function, so we can just return empty
        return ""

    candidate_cves = query_cve_search(structured_data)
    correlated_cves = correlate_cves_with_llm(structured_data, candidate_cves)
    
    routersploit_output = None

    if is_routersploit_installed():

    # STEP A: Check which CVEs match Routersploit modules
        cve_matches = []
        for cve in correlated_cves:
            cve_id = cve.get("cve_id")
            if has_module_for_cve(cve_id):
                cve_matches.append(cve_id)

        # STEP B: If no modules exist, report and skip
        if not cve_matches:
            logging.info("Routersploit has no exploit modules for the correlated CVEs.")
            routersploit_output = "Routersploit has no exploit modules for the identified CVEs."
        else:
            logging.info(f"Routersploit has modules for: {cve_matches}")

            # STEP C: Ask user whether to run exploitation
            user_input = input(
                f"\nRoutersploit has exploit modules for {cve_matches}. Do you want to run them? (y/n): "
            ).strip().lower()

            if user_input == "y":
                logging.info("Running Routersploit exploit modules...")
                routersploit_output = run_routersploit_scan(device.get("ip_str"))
            else:
                routersploit_output = f"User declined to run exploitation modules for: {cve_matches}"

    else:
        logging.info("Routersploit not installed. Skipping.")

    return generate_markdown_report(device, structured_data, correlated_cves, routersploit_output)


def main():
    """
    Main function to orchestrate the entire workflow.
    """
    if not SHODAN_API_KEY:
        logging.critical("FATAL: Shodan API key not found. Please set SHODAN_API_KEY in a .env file.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="AI-Powered Security Analysis Orchestrator")
    parser.add_argument("query", help="The Shodan search query (e.g., 'product:D-Link', 'port:8080')")
    parser.add_argument("-l", "--limit", type=int, default=3, help="Number of devices to analyze from Shodan results.")
    parser.add_argument("-o", "--output", type=str, help="File path to save the markdown report.")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Number of parallel threads to use for analysis.")
    args = parser.parse_args()

    devices = fetch_shodan_data(args.query, args.limit)
    if not devices:
        logging.warning("No devices found for the query. Exiting.")
        sys.exit(0)
    
    reports = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        # Create a future for each device processing task
        future_to_device = {executor.submit(process_device, device): device for device in devices}
        
        for future in as_completed(future_to_device):
            device_ip = future_to_device[future].get('ip_str', 'N/A')
            try:
                report_part = future.result()
                if report_part:
                    reports.append(report_part)
            except Exception as exc:
                logging.error(f"Device {device_ip} generated an exception: {exc}")
    
    final_report = "\n".join(reports)
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(final_report)
        logging.info(f"Report successfully saved to {args.output}")
    else:
        print("\n" + "="*45)
        print("        AI-Powered Security Report         ")
        print("="*45 + "\n")
        print(final_report)

if __name__ == "__main__":
    main()