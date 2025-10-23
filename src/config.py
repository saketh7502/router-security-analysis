import os
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- API Keys and Endpoints ---
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
OLLAMA_API_ENDPOINT = os.getenv("OLLAMA_API_ENDPOINT", "http://localhost:11434/api/generate")
CVE_SEARCH_ENDPOINT = os.getenv("CVE_SEARCH_ENDPOINT", "http://localhost:5000/api")
SHODAN_SEARCH_URL = "https://api.shodan.io/shodan/host/search"

# --- LLM Configuration ---
LLM_MODEL = os.getenv("LLM_MODEL", "llama3:8b")

# --- Analysis Configuration ---
MAX_CVES_TO_CORRELATE = int(os.getenv("MAX_CVES_TO_CORRELATE", 10))