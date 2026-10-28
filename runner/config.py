import os
from pathlib import Path
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai").lower()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-6.1-sol")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.0"))
MANTIS_MAX_POC_TIMEOUT = int(os.getenv("MANTIS_MAX_POC_TIMEOUT", "10"))

# Approximate pricing per 1M tokens (USD)
PRICING_TABLE = {
    # OpenAI
    "gpt-6.1-sol": {"input": 2.50, "output": 10.00},
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4": {"input": 30.00, "output": 60.00},
    # Gemini
    "gemini-3.8-flash": {"input": 0.10, "output": 0.40},
    "gemini-1.5-flash": {"input": 0.075, "output": 0.30},
    "gemini-1.5-pro": {"input": 1.25, "output": 5.00},
    "gemini-2.0-flash": {"input": 0.10, "output": 0.40},
}


def calculate_cost(model_name: str, input_tokens: int, output_tokens: int) -> float:
    matched = None
    for k, v in PRICING_TABLE.items():
        if k in model_name:
            matched = v
            break
    if not matched:
        # Default fallback
        matched = {"input": 2.50, "output": 10.00}
    
    cost = (input_tokens / 1_000_000) * matched["input"] + (output_tokens / 1_000_000) * matched["output"]
    return round(cost, 6)
