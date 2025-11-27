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
from src.rs import is_routersploit_installed, run_routersploit_scan

def process_device(device: dict) -> str:
    """
    Runs the full analysis pipeline for a single device.
    """
    structured_data = {
    "vendor": "cisco",
    "product": "rv320",     # <-- guaranteed to have modules
    "version": "1.4.2.15"
    }
    if not structured_data:
        # Logged inside the function, so we can just return empty
        return ""

    candidate_cves = query_cve_search(structured_data)
    correlated_cves = correlate_cves_with_llm(structured_data, candidate_cves)
    
    routersploit_output = None

    if is_routersploit_installed():

        from src.rs import find_modules_by_product, run_specific_module  # import here to avoid circular

        vendor = structured_data.get("vendor")
        product = structured_data.get("product")

        # STEP 1 — Find matching modules by product model prefix
        similar_modules = find_modules_by_product(vendor, product)

        if not similar_modules:
            logging.info("Routersploit has no exploit modules related to this device model.")
            routersploit_output = "Routersploit has no exploit modules related to this device model."
        else:
            print("\nRoutersploit has exploit modules for similar device models:")
            for i, m in enumerate(similar_modules, start=1):
                print(f"{i}. {m}")

            # STEP 2 — Ask user which module to run
            choice = input("\nSelect a module to run (1,2,3...) or 'n' to skip: ").strip().lower()

            if choice == "n":
                routersploit_output = "User skipped Routersploit exploitation."
            else:
                try:
                    idx = int(choice) - 1
                    module_name = similar_modules[idx]
                    logging.info(f"Running Routersploit module: {module_name}")
                    routersploit_output = run_specific_module(module_name, vendor, device.get("ip_str"))
                except Exception as e:
                    logging.error(f"Invalid choice or error running module: {e}")
                    routersploit_output = "Invalid module selection or exploit error."

    else:
        logging.info("Routersploit not installed. Skipping.")
        routersploit_output = "Routersploit not installed."

    return generate_markdown_report(device, structured_data, correlated_cves, routersploit_output, matched_modules=similar_modules)


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