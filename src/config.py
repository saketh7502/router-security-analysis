import os
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- API Keys and Endpoints ---
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
SHODAN_SEARCH_URL = "https://api.shodan.io/shodan/host/search"
OLLAMA_API_ENDPOINT = os.getenv("OLLAMA_API_ENDPOINT", "http://localhost:11434/api/generate")
NVD_API_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY") # Get a free key from https://nvd.nist.gov/developers/request-an-api-key

# --- LLM Configuration ---
LLM_MODEL = os.getenv("LLM_MODEL", "llama3:8b")

# --- Analysis Configuration ---
MAX_CVES_TO_CORRELATE = int(os.getenv("MAX_CVES_TO_CORRELATE", 10))