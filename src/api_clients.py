import requests
import json
import logging
from typing import List, Dict, Any, Optional

from src.config import (
    SHODAN_API_KEY,
    SHODAN_SEARCH_URL,
    OLLAMA_API_ENDPOINT,
    CVE_SEARCH_ENDPOINT,
    LLM_MODEL
)

# Use a global session for all requests for connection pooling and performance
api_session = requests.Session()

def fetch_shodan_data(query: str, limit: int = 3) -> List[Dict[str, Any]]:
    """
    Pulls a batch of device banners from the Shodan API.
    """
    logging.info(f"Querying Shodan for: '{query}' with a limit of {limit} devices.")
    params = {'key': SHODAN_API_KEY, 'query': query}
    try:
        response = api_session.get(SHODAN_SEARCH_URL, params=params)
        response.raise_for_status()
        data = response.json()
        return data.get('matches', [])[:limit]
    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying Shodan: {e}")
        return []

def parse_banner_with_llm(banner_data: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """
    Sends raw banner data to a local LLM to be parsed into structured JSON.
    """
    raw_banner = banner_data.get('data', '')
    ip_address = banner_data.get('ip_str', 'N/A')
    logging.info(f"Parsing banner for IP: {ip_address}")

    prompt = f"""
    Analyze the following device banner and extract the vendor, product name, and version.
    Your response MUST be a single, raw JSON object with the keys "vendor", "product", and "version".
    If a value cannot be determined, use null.

    Banner:
    {raw_banner}

    JSON:
    """

    payload = {
        "model": LLM_MODEL,
        "prompt": prompt,
        "format": "json",
        "stream": False
    }

    try:
        response = api_session.post(OLLAMA_API_ENDPOINT, json=payload)
        response.raise_for_status()
        parsed_json = json.loads(response.json().get('response', '{}'))
        logging.info(f"  [+] Parsed Data: {parsed_json}")
        return parsed_json
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        logging.error(f"  [!] LLM parsing failed for IP {ip_address}: {e}")
        return None

def query_cve_search(device_data: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Queries a local cve-search instance for candidate vulnerabilities.
    """
    vendor = device_data.get('vendor')
    product = device_data.get('product')

    if not vendor or not product:
        logging.warning("  [-] Skipping CVE search: Missing vendor or product.")
        return []

    url = f"{CVE_SEARCH_ENDPOINT}/search/{vendor}/{product}"
    logging.info(f"Querying cve-search for: {vendor}/{product}")
    try:
        response = api_session.get(url)
        response.raise_for_status()
        cves = response.json().get("data", [])
        logging.info(f"  [+] Found {len(cves)} candidate CVEs.")
        return cves
    except requests.exceptions.RequestException as e:
        logging.error(f"  [!] Error querying cve-search: {e}")
        return []

def correlate_cves_with_llm(device_data: Dict[str, str], cve_list: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """
    Sends device data and candidate CVEs to an LLM for correlation and explanation.
    """
    if not cve_list:
        return []

    logging.info("Correlating CVEs with LLM Agent 2...")
    cve_summaries = [{"id": cve.get('id'), "summary": cve.get('summary')} for cve in cve_list[:MAX_CVES_TO_CORRELATE]]

    prompt = f"""
    You are a cybersecurity vulnerability analyst. Your task is to determine which of the following CVEs are most relevant to the specified device.

    Device Information:
    - Vendor: {device_data.get('vendor')}
    - Product: {device_data.get('product')}
    - Version: {device_data.get('version')}

    Candidate CVEs:
    {json.dumps(cve_summaries, indent=2)}

    Analyze the summary of each CVE. Based on the device information, provide a list of relevant CVEs. For each relevant CVE, provide a concise, one-sentence explanation of the risk. Your response MUST be a single, raw JSON object containing a list under the key "relevant_cves". Each item in the list should have two keys: "cve_id" and "explanation". If no CVEs are relevant, return an empty list.

    JSON:
    """

    payload = {"model": LLM_MODEL, "prompt": prompt, "format": "json", "stream": False}

    try:
        response = api_session.post(OLLAMA_API_ENDPOINT, json=payload)
        response.raise_for_status()
        correlation_result = json.loads(response.json().get('response', '{}'))
        relevant_cves = correlation_result.get('relevant_cves', [])
        logging.info(f"  [+] Correlation complete. Found {len(relevant_cves)} relevant CVEs.")
        return relevant_cves
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        logging.error(f"  [!] LLM correlation failed: {e}")
        return []