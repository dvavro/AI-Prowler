#!/usr/bin/env python3
"""
AI Prowler Document Preprocessor
Indexes local files and allows semantic search + LLM queries

Author: David
Version: 1.8 (with per-email incremental indexing for all email types)
Date: February 2026
"""

# CRITICAL: Set environment variables BEFORE any imports to suppress warnings
import os
import sys

# Suppress all warnings from libraries
os.environ['TOKENIZERS_PARALLELISM'] = 'false'
os.environ['HF_HUB_DISABLE_TELEMETRY'] = '1'
os.environ['HF_HUB_DISABLE_PROGRESS_BARS'] = '1'
os.environ['HF_HUB_DISABLE_SYMLINKS_WARNING'] = '1'
os.environ['TRANSFORMERS_VERBOSITY'] = 'error'
os.environ['TRANSFORMERS_NO_ADVISORY_WARNINGS'] = '1'

# Suppress Python warnings
import warnings
warnings.filterwarnings('ignore')
warnings.simplefilter('ignore')

# Now safe to import everything else
import json
import argparse
from pathlib import Path
from typing import List, Dict, Optional
import requests
from datetime import datetime
import time
import threading

# Email support
import email
from email import policy
from email.parser import BytesParser
import mailbox
import re

# Third-party imports (install via requirements.txt)
# Temporarily redirect stderr to suppress import warnings
import io
import contextlib

@contextlib.contextmanager
def suppress_stderr():
    """Temporarily suppress stderr output"""
    old_stderr = sys.stderr
    sys.stderr = io.StringIO()
    try:
        yield
    finally:
        sys.stderr = old_stderr

try:
    with suppress_stderr():
        import chromadb
        from chromadb.utils import embedding_functions
        import pdfplumber
        from docx import Document as DocxDocument
except ImportError as e:
    print(f"❌ Missing dependency: {e}")
    print("Please run: pip install -r requirements.txt")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════

# Default settings
OLLAMA_URL = "http://localhost:11434"
OLLAMA_MODEL = "llama3.2:1b"
CHROMA_DB_PATH = "./rag_database"
COLLECTION_NAME = "documents"
CHUNK_SIZE = 500  # words per chunk
CHUNK_OVERLAP = 50  # words overlap between chunks
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

def normalise_path(filepath: str) -> str:
    """
    Normalise a file path to forward slashes for consistent storage and lookup.

    On Windows, filedialog returns forward slashes but Path.resolve() returns
    backslashes. If we store one form in ChromaDB metadata and query with the
    other, collection.delete(where={"filepath": ...}) silently matches nothing
    and stale chunks from modified files are never removed.

    Using forward slashes everywhere (as Python's pathlib does on all platforms)
    gives a single canonical form safe for cross-platform use and JSON storage.
    """
    return str(filepath).replace('\\', '/')

# When False, rag_query only prints the AI answer — no headers, chunk info,
# source list, or timing. Saved to config so the GUI toggle persists.
SHOW_SOURCES  = False  # default: clean answer-only mode

# Set to True by the GUI Stop button to abort a streaming query mid-response.
# query_ollama() checks this flag on every token and exits the stream early.
# Always reset to False before starting a new query.
QUERY_STOP    = False

# When True, prints all 🔬/⏱ timing and debug output to the answer box.
# When False (default) all debug lines are suppressed — clean answer only.
# Controlled by "Enable debug output" checkbox in Settings → Query Output.
DEBUG_OUTPUT  = False

# GPU_LAYERS: number of model layers to offload to the GPU for Ollama.
#   0  = CPU only (no GPU)
#  -1  = offload ALL layers automatically (Ollama decides how many fit in VRAM)
#  1-N = partial offload — useful for laptops with limited VRAM
# Sent as num_gpu in every Ollama API call.
GPU_LAYERS = -1   # -1 = auto (Ollama decides based on available VRAM)

# Model context window sizes (in tokens, approximate)
MODEL_CONTEXT_WINDOWS = {
    # Llama 3.2 models
    "llama3.2:1b": 128000,
    "llama3.2:3b": 128000,
    
    # Llama 3.1 models
    "llama3.1:8b": 128000,
    "llama3.1:70b": 128000,
    "llama3.1:405b": 128000,
    
    # Llama 3 models
    "llama3:8b": 8192,
    "llama3:70b": 8192,
    
    # Qwen models
    "qwen2.5:0.5b": 32768,
    "qwen2.5:1.5b": 32768,
    "qwen2.5:3b": 32768,
    "qwen2.5:7b": 128000,
    "qwen2.5:14b": 128000,
    "qwen2.5:32b": 128000,
    "qwen2.5:72b": 128000,
    
    # Mistral models
    "mistral:7b": 32768,
    "mixtral:8x7b": 32768,
    "mixtral:8x22b": 65536,
    
    # Gemma models
    "gemma:2b": 8192,
    "gemma:7b": 8192,
    "gemma2:9b": 8192,
    "gemma2:27b": 8192,
    
    # Default fallback
    "default": 8192
}

# Model metadata: download size (GB) and minimum RAM required (GB)
# size_gb  = approximate download size from Ollama registry
# min_ram_gb = minimum system RAM to run at acceptable speed (CPU inference)
MODEL_INFO = {
    # Llama 3.2 models
    "llama3.2:1b":   {"maker": "Meta",       "size_gb": 1.3,  "min_ram_gb": 4,   "description": "Fastest, great for quick queries"},
    "llama3.2:3b":   {"maker": "Meta",       "size_gb": 2.0,  "min_ram_gb": 6,   "description": "Good balance of speed and quality"},
    # Llama 3.1 models
    "llama3.1:8b":   {"maker": "Meta",       "size_gb": 4.7,  "min_ram_gb": 8,   "description": "Strong general-purpose model"},
    "llama3.1:70b":  {"maker": "Meta",       "size_gb": 40.0, "min_ram_gb": 48,  "description": "Very capable, needs high-end hardware"},
    "llama3.1:405b": {"maker": "Meta",       "size_gb": 231.0,"min_ram_gb": 256, "description": "Frontier model, requires server-grade RAM"},
    # Llama 3 models
    "llama3:8b":     {"maker": "Meta",       "size_gb": 4.7,  "min_ram_gb": 8,   "description": "Solid 8B model (older generation)"},
    "llama3:70b":    {"maker": "Meta",       "size_gb": 40.0, "min_ram_gb": 48,  "description": "Large model (older generation)"},
    # Qwen models
    "qwen2.5:0.5b":  {"maker": "Alibaba",    "size_gb": 0.4,  "min_ram_gb": 2,   "description": "Ultra-lightweight, fastest possible"},
    "qwen2.5:1.5b":  {"maker": "Alibaba",    "size_gb": 1.0,  "min_ram_gb": 4,   "description": "Very fast, surprisingly capable"},
    "qwen2.5:3b":    {"maker": "Alibaba",    "size_gb": 1.9,  "min_ram_gb": 6,   "description": "Efficient and capable small model"},
    "qwen2.5:7b":    {"maker": "Alibaba",    "size_gb": 4.7,  "min_ram_gb": 8,   "description": "Excellent quality-to-speed ratio"},
    "qwen2.5:14b":   {"maker": "Alibaba",    "size_gb": 9.0,  "min_ram_gb": 16,  "description": "High quality, needs 16GB+ RAM"},
    "qwen2.5:32b":   {"maker": "Alibaba",    "size_gb": 20.0, "min_ram_gb": 32,  "description": "Near-frontier quality on CPU"},
    "qwen2.5:72b":   {"maker": "Alibaba",    "size_gb": 47.0, "min_ram_gb": 64,  "description": "Top-tier quality, high RAM needed"},
    # Mistral models
    "mistral:7b":    {"maker": "Mistral AI", "size_gb": 4.1,  "min_ram_gb": 8,   "description": "Fast and efficient 7B model"},
    "mixtral:8x7b":  {"maker": "Mistral AI", "size_gb": 26.0, "min_ram_gb": 48,  "description": "Mixture-of-experts, high quality"},
    "mixtral:8x22b": {"maker": "Mistral AI", "size_gb": 80.0, "min_ram_gb": 128, "description": "Very large MoE model"},
    # Gemma models
    "gemma:2b":      {"maker": "Google",     "size_gb": 1.7,  "min_ram_gb": 4,   "description": "Compact and efficient model"},
    "gemma:7b":      {"maker": "Google",     "size_gb": 5.0,  "min_ram_gb": 8,   "description": "Solid 7B general-purpose model"},
    "gemma2:9b":     {"maker": "Google",     "size_gb": 5.5,  "min_ram_gb": 8,   "description": "Improved Gemma, strong at 9B"},
    "gemma2:27b":    {"maker": "Google",     "size_gb": 16.0, "min_ram_gb": 32,  "description": "Large model, high quality output"},
}

# ═══════════════════════════════════════════════════════════
# EXTERNAL LLM PROVIDERS
# ═══════════════════════════════════════════════════════════

EXTERNAL_PROVIDERS = {
    'local':     {'name': 'Local Ollama',  'maker': 'Local',      'model': None,                             'url': None,                                                                                  'auth': None,        'color': '#888888', 'key_url': None},
    'openai':    {'name': 'ChatGPT',       'maker': 'OpenAI',     'model': 'gpt-4o',                         'url': 'https://api.openai.com/v1/chat/completions',                                          'auth': 'Bearer',    'color': '#10a37f', 'key_url': 'https://platform.openai.com/api-keys'},
    'anthropic': {'name': 'Claude',        'maker': 'Anthropic',  'model': 'claude-opus-4-5',                'url': 'https://api.anthropic.com/v1/messages',                                               'auth': 'x-api-key', 'color': '#d4691e', 'key_url': 'https://console.anthropic.com/settings/keys'},
    'google':    {'name': 'Gemini',        'maker': 'Google',     'model': 'gemini-2.0-flash',               'url': 'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent',      'auth': 'key_param', 'color': '#4285f4', 'key_url': 'https://aistudio.google.com/app/apikey'},
    'xai':       {'name': 'Grok',          'maker': 'xAI',        'model': 'grok-beta',                      'url': 'https://api.x.ai/v1/chat/completions',                                                'auth': 'Bearer',    'color': '#1da1f2', 'key_url': 'https://console.x.ai/'},
    'meta':      {'name': 'Llama API',     'maker': 'Meta',       'model': 'Llama-4-Scout-17B-16E-Instruct', 'url': 'https://api.llama.com/v1/chat/completions',                                           'auth': 'Bearer',    'color': '#0866ff', 'key_url': 'https://llama.developer.meta.com/'},
    'mistral':   {'name': 'Mistral Large', 'maker': 'Mistral AI', 'model': 'mistral-large-latest',           'url': 'https://api.mistral.ai/v1/chat/completions',                                          'auth': 'Bearer',    'color': '#ff7000', 'key_url': 'https://console.mistral.ai/api-keys/'},
}

# Currently active provider — 'local' uses Ollama, others call external APIs
ACTIVE_PROVIDER = 'local'

# API keys: {provider_id: api_key_string}
PROVIDER_API_KEYS: dict = {}

# Rate-limit timeouts: {provider_id: unix_timestamp_when_available_again}
PROVIDER_TIMEOUTS: dict = {}

# When True, fall back to local Ollama if an external provider call fails
FALLBACK_TO_LOCAL = True


def get_provider_status(provider_id: str) -> str:
    """
    Returns one of:
      'local'    — the local Ollama provider
      'ready'    — external, key present, not rate-limited
      'timeout'  — external, currently rate-limited
      'no_key'   — external, no API key configured
    """
    if provider_id == 'local':
        return 'local'
    key = PROVIDER_API_KEYS.get(provider_id, '').strip()
    if not key:
        return 'no_key'
    until = PROVIDER_TIMEOUTS.get(provider_id, 0)
    if until and time.time() < until:
        return 'timeout'
    return 'ready'


def get_provider_timeout_str(provider_id: str) -> str:
    """Returns human-readable string like 'until 3:45 PM', or empty string."""
    until = PROVIDER_TIMEOUTS.get(provider_id, 0)
    if until and time.time() < until:
        import datetime as _dt
        return f"until {_dt.datetime.fromtimestamp(until).strftime('%I:%M %p')}"
    return ''


def set_provider_timeout(provider_id: str, seconds: int = 3600):
    """Mark a provider as rate-limited for the given number of seconds."""
    PROVIDER_TIMEOUTS[provider_id] = time.time() + seconds


def query_external_llm(provider_id: str, prompt: str, max_tokens: int = 2000, images_b64: list = None) -> str:
    """
    Route prompt to the chosen external LLM API, return answer text.
    Supports OpenAI-compatible (Bearer), Anthropic (x-api-key), Google (key_param).
    Automatically sets a rate-limit timeout on HTTP 429 responses.
    Returns a string starting with \\n\\n❌ on any error (triggers fallback in rag_query).
    """
    import json as _json
    prov   = EXTERNAL_PROVIDERS[provider_id]
    apikey = PROVIDER_API_KEYS.get(provider_id, '').strip()
    model  = prov['model']
    # Allow {model} placeholder in URL (used by Gemini so URL stays in sync with model)
    url    = prov['url'].replace('{model}', model) if prov['url'] else ''
    auth   = prov['auth']

    if not apikey:
        return (f"\n\n❌ No API key for {prov['name']}.\n"
                f"Add your key in Settings → External AI APIs.")

    headers = {'Content-Type': 'application/json'}
    params  = {}

    if auth == 'Bearer':
        headers['Authorization'] = f"Bearer {apikey}"
        if images_b64:
            img_content = [{'type': 'text', 'text': prompt}]
            for img in images_b64:
                img_content.append({'type': 'image_url',
                                    'image_url': {'url': f'data:image/png;base64,{img}'}})
            payload = {'model': model, 'messages': [{'role': 'user', 'content': img_content}], 'max_tokens': max_tokens}
        else:
            payload = {'model': model, 'messages': [{'role': 'user', 'content': prompt}], 'max_tokens': max_tokens}

    elif auth == 'x-api-key':
        headers['x-api-key']         = apikey
        headers['anthropic-version'] = '2023-06-01'
        if images_b64:
            img_content = []
            for img in images_b64:
                img_content.append({'type': 'image',
                                    'source': {'type': 'base64', 'media_type': 'image/png', 'data': img}})
            img_content.append({'type': 'text', 'text': prompt})
            payload = {'model': model, 'max_tokens': max_tokens,
                       'messages': [{'role': 'user', 'content': img_content}]}
        else:
            payload = {'model': model, 'max_tokens': max_tokens, 'messages': [{'role': 'user', 'content': prompt}]}

    elif auth == 'key_param':
        params['key'] = apikey
        if images_b64:
            parts = []
            for img in images_b64:
                parts.append({'inline_data': {'mime_type': 'image/png', 'data': img}})
            parts.append({'text': prompt})
            payload = {'contents': [{'parts': parts}],
                       'generationConfig': {'maxOutputTokens': max_tokens}}
        else:
            payload = {'contents': [{'parts': [{'text': prompt}]}],
                       'generationConfig': {'maxOutputTokens': max_tokens}}
    else:
        return "\n\n❌ Unknown auth style for this provider."

    try:
        resp = requests.post(url, json=payload, headers=headers, params=params, timeout=120)

        if resp.status_code == 429:
            # Use the retry-after header if present, but cap at 5 minutes for
            # free-tier providers that incorrectly report 1-hour timeouts
            retry_after = min(int(resp.headers.get('retry-after', 300)), 300)
            set_provider_timeout(provider_id, retry_after)
            import datetime as _dt
            until_str = _dt.datetime.fromtimestamp(time.time() + retry_after).strftime('%I:%M %p')
            return (f"\n\n❌ {prov['name']} rate limit reached. Quota resets at {until_str}.\n"
                    f"Free tier allows ~15 requests/minute. Falling back to local Ollama.")

        if resp.status_code == 401:
            return (f"\n\n❌ {prov['name']}: Invalid API key (HTTP 401).\n"
                    f"Check your key in Settings → External AI APIs.")

        if resp.status_code == 403:
            return (f"\n\n❌ {prov['name']}: Access denied (HTTP 403).\n"
                    f"Your key may not have access to model '{model}'.\n"
                    f"Check your account permissions at the provider's console.")

        if not resp.ok:
            # Try to extract a useful message from the response body
            try:
                err_body = resp.json()
                err_msg  = (err_body.get('error', {}).get('message')
                            or err_body.get('message')
                            or resp.text[:300])
            except Exception:
                err_msg = resp.text[:300]
            return f"\n\n❌ {prov['name']} API error (HTTP {resp.status_code}): {err_msg}"

        data = resp.json()

        if auth == 'Bearer':
            return data['choices'][0]['message']['content']

        elif auth == 'x-api-key':
            return data['content'][0]['text']

        elif auth == 'key_param':
            # Gemini may return 200 OK but with no candidates if content was blocked
            candidates = data.get('candidates', [])
            if not candidates:
                block_reason = data.get('promptFeedback', {}).get('blockReason', 'unknown')
                return (f"\n\n❌ {prov['name']}: Response blocked by safety filters "
                        f"(reason: {block_reason}).\nTry rephrasing your question.")
            finish = candidates[0].get('finishReason', '')
            if finish == 'SAFETY':
                return (f"\n\n❌ {prov['name']}: Response blocked — SAFETY filter triggered.\n"
                        f"Try rephrasing your question.")
            try:
                return candidates[0]['content']['parts'][0]['text']
            except (KeyError, IndexError) as ke:
                return (f"\n\n❌ {prov['name']}: Unexpected response format — {ke}\n"
                        f"Raw response: {str(data)[:300]}")

    except requests.exceptions.Timeout:
        return f"\n\n❌ {prov['name']} timed out after 120s."
    except requests.exceptions.ConnectionError:
        return f"\n\n❌ Cannot reach {prov['name']}. Check your internet connection."
    except Exception as exc:
        return f"\n\n❌ {prov['name']} error: {type(exc).__name__}: {exc}"

    return "\n\n❌ Unknown error."


def test_provider_connection(provider_id: str, api_key: str = None) -> dict:
    """
    Fire a tiny 'say hello' request to verify a provider key works end-to-end.
    Uses the key supplied (not-yet-saved entry box value) or falls back to stored key.

    Returns a dict:
      ok        bool   — True = got a real reply
      status    int    — HTTP status code (0 = no network)
      provider  str    — display name
      model     str    — model string used
      message   str    — one-line human summary (shown in popup header)
      detail    str    — full diagnostic text (shown in popup body)
    """
    prov  = EXTERNAL_PROVIDERS.get(provider_id, {})
    name  = prov.get('name', provider_id)
    model = prov.get('model', '')
    auth  = prov.get('auth')
    url   = (prov.get('url') or '').replace('{model}', model)
    key   = (api_key or PROVIDER_API_KEYS.get(provider_id, '')).strip()

    def _r(ok, status, message, detail=''):
        return {'ok': ok, 'status': status, 'provider': name,
                'model': model, 'message': message, 'detail': detail}

    if not key:
        return _r(False, 0, 'No API key entered.',
                  'Type or paste your API key then click Test.')
    if not url:
        return _r(False, 0, 'Local Ollama does not need a connection test.', '')

    headers = {'Content-Type': 'application/json'}
    params  = {}
    ping    = "Reply with exactly one word: CONNECTED"

    if auth == 'Bearer':
        headers['Authorization'] = f"Bearer {key}"
        payload = {'model': model,
                   'messages': [{'role': 'user', 'content': ping}],
                   'max_tokens': 10}
    elif auth == 'x-api-key':
        headers['x-api-key']         = key
        headers['anthropic-version'] = '2023-06-01'
        payload = {'model': model, 'max_tokens': 10,
                   'messages': [{'role': 'user', 'content': ping}]}
    elif auth == 'key_param':
        params['key'] = key
        payload = {'contents': [{'parts': [{'text': ping}]}],
                   'generationConfig': {'maxOutputTokens': 10}}
    else:
        return _r(False, 0, f'Unknown auth style: {auth}')

    try:
        resp   = requests.post(url, json=payload, headers=headers,
                               params=params, timeout=20)
        status = resp.status_code
        try:
            body = resp.json()
        except Exception:
            body = {}
        raw = resp.text[:600]

        def _err_msg():
            return (body.get('error', {}).get('message')
                    or body.get('message') or raw)

        if status == 200:
            try:
                if auth == 'Bearer':
                    reply = body['choices'][0]['message']['content'].strip()
                elif auth == 'x-api-key':
                    reply = body['content'][0]['text'].strip()
                elif auth == 'key_param':
                    cands = body.get('candidates', [])
                    if not cands:
                        block = body.get('promptFeedback', {}).get('blockReason', 'unknown')
                        return _r(False, 200,
                                  f'Connected but response blocked (reason: {block}).',
                                  raw)
                    reply = cands[0]['content']['parts'][0]['text'].strip()
                detail = (f"Provider : {name}\n"
                          f"Model    : {model}\n"
                          f"HTTP     : 200 OK\n"
                          f"Reply    : {reply}")
                return _r(True, 200,
                          f'✅ Connected!  Model replied: "{reply}"', detail)
            except (KeyError, IndexError) as e:
                return _r(False, 200,
                          'Connected but response format was unexpected.',
                          f'Parse error: {e}\n\nRaw response:\n{raw}')

        elif status == 401:
            return _r(False, 401,
                      '❌ Invalid API key — rejected by server (HTTP 401).',
                      f'The key you entered was not accepted.\n'
                      f'Double-check you copied the full key.\n\n{_err_msg()}')

        elif status == 403:
            return _r(False, 403,
                      f'❌ Access denied (HTTP 403) — key valid but no access to "{model}".',
                      f'Your key works but may not have permission to use model "{model}".\n'
                      f'Check your plan at {prov.get("key_url","the provider console")}.\n\n{_err_msg()}')

        elif status == 404:
            return _r(False, 404,
                      f'❌ Model not found (HTTP 404) — "{model}" may not exist on your plan.',
                      f'The model name "{model}" was not recognised.\n'
                      f'Your plan may use a different model name.\n\n{_err_msg()}')

        elif status == 429:
            retry = int(resp.headers.get('retry-after', 300))
            import datetime as _dt
            until = _dt.datetime.fromtimestamp(time.time() + retry).strftime('%I:%M %p')
            return _r(False, 429,
                      f'⚠️ Key is valid but rate-limited until {until}.',
                      f'Free tier limit reached. Wait ~{retry}s and try again.\n\n{raw}')

        else:
            return _r(False, status,
                      f'❌ HTTP {status} error.',
                      f'Server returned an unexpected status.\n\n{_err_msg()}')

    except requests.exceptions.Timeout:
        return _r(False, 0, '❌ Timed out after 20s.',
                  'Server did not respond. Check your internet connection.')
    except requests.exceptions.ConnectionError as e:
        return _r(False, 0, f'❌ Cannot reach {name}.',
                  f'Network error — check your internet connection.\n\n{e}')
    except Exception as e:
        return _r(False, 0, f'❌ Unexpected error: {type(e).__name__}', str(e))


# GUI_MODE: set to True by rag_gui.py before calling any functions.
# When True, the terminal spinner is disabled and replaced with simple
# periodic progress lines that are safe for the Tkinter output queue.
GUI_MODE = False

# Module-level cache for ChromaDB client and embedding model.
# Populated on first get_chroma_client() call; reused for all subsequent
# calls so the embedding model (all-MiniLM-L6-v2) is only loaded once.
_chroma_client_cache = None
_embedding_func_cache = None

# Configuration file location
CONFIG_FILE = Path.home() / '.rag_config.json'

def load_config():
    """Load configuration from file"""
    global OLLAMA_MODEL, OLLAMA_URL, CHUNK_SIZE, CHUNK_OVERLAP, SHOW_SOURCES, GPU_LAYERS, DEBUG_OUTPUT
    global ACTIVE_PROVIDER, PROVIDER_API_KEYS, PROVIDER_TIMEOUTS

    config = {}
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                OLLAMA_MODEL     = config.get('model',           OLLAMA_MODEL)
                OLLAMA_URL       = config.get('url',             OLLAMA_URL)
                CHUNK_SIZE       = config.get('chunk_size',      CHUNK_SIZE)
                CHUNK_OVERLAP    = config.get('chunk_overlap',   CHUNK_OVERLAP)
                SHOW_SOURCES     = config.get('show_sources',    SHOW_SOURCES)
                GPU_LAYERS       = config.get('gpu_layers',      GPU_LAYERS)
                DEBUG_OUTPUT     = config.get('debug_output',    DEBUG_OUTPUT)
                ACTIVE_PROVIDER  = config.get('active_provider', ACTIVE_PROVIDER)
                PROVIDER_API_KEYS= config.get('provider_api_keys', {})
                # Load timeouts but discard any that have already expired
                raw_timeouts = config.get('provider_timeouts', {})
                now = time.time()
                PROVIDER_TIMEOUTS = {k: v for k, v in raw_timeouts.items() if v > now}
        except:
            pass

    return config


def load_extension_config():
    """
    Merge user-customised extension lists from config into the live global sets.
    Called once at startup so custom additions survive restarts.

    Config keys used:
      'ext_supported_add'  : list of extensions to ADD to SUPPORTED_EXTENSIONS
      'ext_supported_remove': list of extensions to REMOVE from SUPPORTED_EXTENSIONS
      'ext_skipped_add'    : list of extensions to ADD to SKIP_EXTENSIONS
      'ext_skipped_remove' : list of extensions to REMOVE from SKIP_EXTENSIONS
      'dir_skipped_add'    : list of directory names to ADD to SKIP_DIRECTORIES
      'dir_skipped_remove' : list of directory names to REMOVE from SKIP_DIRECTORIES
    """
    global SUPPORTED_EXTENSIONS, SKIP_EXTENSIONS, SKIP_DIRECTORIES

    if not CONFIG_FILE.exists():
        return

    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
    except Exception:
        return

    def _norm_ext(e):
        e = e.strip().lower()
        return e if e.startswith('.') else '.' + e

    for ext in config.get('ext_supported_add', []):
        SUPPORTED_EXTENSIONS.add(_norm_ext(ext))
    for ext in config.get('ext_supported_remove', []):
        SUPPORTED_EXTENSIONS.discard(_norm_ext(ext))
    for ext in config.get('ext_skipped_add', []):
        SKIP_EXTENSIONS.add(_norm_ext(ext))
    for ext in config.get('ext_skipped_remove', []):
        SKIP_EXTENSIONS.discard(_norm_ext(ext))
    for d in config.get('dir_skipped_add', []):
        SKIP_DIRECTORIES.add(d.strip())
    for d in config.get('dir_skipped_remove', []):
        SKIP_DIRECTORIES.discard(d.strip())

def save_config(model=None, url=None, chunk_size=None, chunk_overlap=None,
                show_sources=None, gpu_layers=None, mic_silence_secs=None,
                debug_output=None, debug_view=None, auto_start_ollama=None,
                active_provider=None, provider_api_keys=None, provider_timeouts=None):
    """Save configuration to file"""
    config = {}

    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        except:
            pass

    if model              is not None: config['model']              = model
    if url                is not None: config['url']                = url
    if chunk_size         is not None: config['chunk_size']         = chunk_size
    if chunk_overlap      is not None: config['chunk_overlap']      = chunk_overlap
    if show_sources       is not None: config['show_sources']       = show_sources
    if gpu_layers         is not None: config['gpu_layers']         = gpu_layers
    if mic_silence_secs   is not None: config['mic_silence_secs']   = mic_silence_secs
    if debug_output       is not None: config['debug_output']       = debug_output
    if debug_view         is not None: config['debug_view']         = debug_view
    if auto_start_ollama  is not None: config['auto_start_ollama']  = auto_start_ollama
    if active_provider    is not None: config['active_provider']    = active_provider
    if provider_api_keys  is not None: config['provider_api_keys']  = provider_api_keys
    if provider_timeouts  is not None: config['provider_timeouts']  = provider_timeouts

    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except:
        return False


def save_extension_config(supported_extensions: set, skipped_extensions: set,
                          skipped_directories: set):
    """
    Persist the current (user-modified) extension and directory sets to config.

    Stores deltas relative to the built-in defaults so the file stays small
    and readable.  Also stores the full current sets for direct reload.
    """
    # Compute built-in defaults (re-import to compare cleanly)
    from importlib import import_module
    import importlib, types

    # We store the full current sets — simplest and most reliable approach
    config = {}
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        except Exception:
            pass

    config['ext_supported_current']  = sorted(supported_extensions)
    config['ext_skipped_current']    = sorted(skipped_extensions)
    config['dir_skipped_current']    = sorted(skipped_directories)

    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception:
        return False


def load_full_extension_config():
    """
    Load the full saved extension sets if they exist, otherwise return the
    built-in defaults.  Returns (supported_set, skipped_set, dir_set).
    """
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            if 'ext_supported_current' in config:
                return (
                    set(config['ext_supported_current']),
                    set(config['ext_skipped_current']),
                    set(config['dir_skipped_current']),
                )
        except Exception:
            pass
    return (set(SUPPORTED_EXTENSIONS), set(SKIP_EXTENSIONS), set(SKIP_DIRECTORIES))

def get_model_context_window(model_name):
    """Get context window size for a model"""
    # Try exact match
    if model_name in MODEL_CONTEXT_WINDOWS:
        return MODEL_CONTEXT_WINDOWS[model_name]
    
    # Try base model name (without version tag)
    base_name = model_name.split(':')[0] if ':' in model_name else model_name
    for key in MODEL_CONTEXT_WINDOWS:
        if key.startswith(base_name):
            return MODEL_CONTEXT_WINDOWS[key]
    
    # Default fallback
    return MODEL_CONTEXT_WINDOWS["default"]

def calculate_optimal_chunks(model_name, max_chunks=3):
    """Calculate optimal number of chunks based on model context window.

    Capped at 3 (default).  Each chunk ≈ 500 words / 750 tokens, so 3 chunks
    ≈ 2,250 context tokens.  With 2,512 reserved for the system prompt +
    question + response (2000 tokens) that totals ≈ 4,750 tokens — comfortably 
    inside the 8,192 default num_ctx with plenty of headroom.
    """
    context_window   = get_model_context_window(model_name)
    available_tokens = context_window - 2500   # headroom for prompt+response (2000 tokens)
    tokens_per_chunk = 750
    max_possible     = available_tokens // tokens_per_chunk
    return min(max_possible, max_chunks)


# ─────────────────────────────────────────────────────────────────────────────
# num_ctx helpers
#
# CRITICAL RULE: prewarm_ollama() and every query_ollama() call MUST use the
# SAME num_ctx value.  If they differ, Ollama silently unloads and reloads the
# model between the prewarm and the first real query — causing 5-8 min delay.
#
# How the GUI "Context Chunks" dropdown maps to token counts:
#
#   Chunks | Context tokens | + 500 response | Total needed | Safe @ 8192?
#   -------+----------------+----------------+--------------+-------------
#   Auto=5 |   ~3,750       |    4,250       |   4,250      |  ✅ Yes
#     3    |   ~2,250       |    2,750       |   2,750      |  ✅ Yes
#     7    |   ~5,250       |    5,750       |   5,750      |  ✅ Yes
#    10    |   ~7,500       |    8,000       |   8,000      |  ⚠️ Borderline
#    15    |  ~11,250       |   11,750       |  11,750      |  ❌ Bumps to 12288
#    20    |  ~15,000       |   15,500       |  15,500      |  ❌ Bumps to 16384
#
# When the user picks 15 or 20 chunks, safe_num_ctx_for_prompt() bumps num_ctx
# automatically AND prewarm_ollama() is called again with the new value so the
# model is reloaded ONCE (intentionally) rather than silently mid-query.
# ─────────────────────────────────────────────────────────────────────────────

_MODEL_NUM_CTX = {
    # Small models — 8192 gives plenty of headroom for ≤7 chunks
    "llama3.2:1b":   8192,
    "qwen2.5:0.5b":  8192,
    "qwen2.5:1.5b":  8192,
    "gemma:2b":      8192,
    "phi3:mini":     8192,
    # Mid-range 3b-8b
    "llama3.2:3b":   8192,
    "qwen2.5:3b":    8192,
    "llama3.1:8b":   8192,
    "qwen2.5:7b":    8192,
    "mistral:7b":    8192,
    "gemma:7b":      8192,
    # Large
    "llama3.1:70b":  16384,
    "qwen2.5:14b":   16384,
    "qwen2.5:32b":   16384,
    "mixtral:8x7b":  16384,
    "default":       8192,
}

def get_model_num_ctx(model_name: str) -> int:
    """Return the baseline num_ctx for a model.

    This is the value used for prewarm and for queries where the prompt fits
    within the window.  Use safe_num_ctx_for_prompt() when you have an actual
    assembled prompt and need a guaranteed-safe value.
    """
    if model_name in _MODEL_NUM_CTX:
        return _MODEL_NUM_CTX[model_name]
    base = model_name.split(":")[0] if ":" in model_name else model_name
    for key, val in _MODEL_NUM_CTX.items():
        if key.startswith(base):
            return val
    return _MODEL_NUM_CTX["default"]


def safe_num_ctx_for_prompt(prompt: str, max_tokens: int, model_name: str) -> int:
    """Return the smallest num_ctx that fits prompt + response without overflow.

    CALIBRATED — measured from live Ollama output (prompt_eval_count field):
      5-chunk prompt: 2,566 words → 4,974 actual tokens  (ratio = 1.94 t/w)
      Old × 1.5 estimate = 3,849 → underestimate by 29% → Ollama silently
      hangs in streaming mode when context overflows, then corrupts model state
      so subsequent queries also fail until a full reload.

      Fix: use × 2.0 (safely above measured 1.94 ratio) + 512 safety buffer.

    Chunk capacity at each num_ctx with × 2.0 estimator (750 words/chunk):
      8,192  → max ~3 chunks before reload    (1b-8b models default)
      16,384 → max ~9 chunks before reload    (14b-70b models default)

    Steps:
      1. Estimate token count (words × 2.0).
      2. Add max_tokens + 512 safety buffer.
      3. If fits in baseline num_ctx → return baseline (no reload).
      4. If overflows → round up to next 1,024 and warn. Caller re-prewarns.
    """
    import math
    base_ctx      = get_model_num_ctx(model_name)
    prompt_tokens = int(len(prompt.split()) * 2.0)   # calibrated: actual ~1.94 t/w
    needed        = prompt_tokens + max_tokens + 512  # 512 = safety buffer
    if needed > base_ctx:
        bumped = math.ceil(needed / 1024) * 1024
        print(f"⚠️  CONTEXT OVERFLOW: prompt ~{prompt_tokens} tok + {max_tokens} response "
              f"= {needed} tok  >  num_ctx {base_ctx}.  "
              f"Bumping num_ctx → {bumped}.  "
              f"This triggers a model reload (~2min on CPU). "
              f"Use 3 or fewer chunks to stay within {base_ctx} and avoid this.")
        return bumped
    return base_ctx

# Load config at startup
load_config()

# Supported file extensions — content-bearing files worth indexing
SUPPORTED_EXTENSIONS = {
    # Documents
    '.txt', '.md', '.rst', '.rtf', '.odt',
    '.pdf', '.docx', '.doc', '.xlsx', '.xls', '.pptx', '.ppt',
    # Code / markup
    '.py', '.js', '.ts', '.jsx', '.tsx', '.cs', '.java', '.cpp', '.c', '.h',
    '.hpp', '.go', '.rs', '.rb', '.php', '.swift', '.kt', '.scala', '.r',
    '.html', '.htm', '.css', '.scss', '.sass', '.less', '.xml', '.xhtml',
    '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.env',
    # Data / logs
    '.csv', '.tsv', '.log', '.sql',
    # Email — single-message files (one email per file)
    '.eml', '.msg', '.emlx',
    # Email — archive/export files (multiple messages, handled by incremental indexer)
    '.mbox',   # Gmail Takeout, Thunderbird, Apple Mail export, Yahoo (via tools)
    '.rmail',  # GNU Emacs RMAIL / Babyl format
    '.babyl',  # GNU Babyl (alternate extension)
    '.mmdf',   # MMDF format (legacy Unix / SCO)
    # Scripts / config
    '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
    '.gitignore', '.dockerignore', '.editorconfig',
}

# Extensions to always skip — binary, compiled, executable, media, archive
SKIP_EXTENSIONS = {
    # Executables & compiled binaries
    '.exe', '.dll', '.so', '.dylib', '.lib', '.a', '.o', '.obj',
    '.class', '.pyc', '.pyd', '.pyo', '.pdb', '.ilk', '.exp',
    '.com', '.scr', '.sys', '.drv', '.ocx', '.ax',
    # Archives & packages
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.tgz',
    '.jar', '.war', '.ear', '.whl', '.egg', '.nupkg', '.vsix',
    '.deb', '.rpm', '.msi', '.pkg', '.dmg', '.iso', '.img',
    # Media — images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif',
    '.webp', '.ico', '.svg', '.psd', '.ai', '.eps', '.raw',
    '.cr2', '.nef', '.orf', '.arw',
    # Media — audio / video
    '.mp3', '.mp4', '.wav', '.flac', '.aac', '.ogg', '.wma',
    '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v',
    '.m4a', '.opus', '.aiff',
    # Fonts
    '.ttf', '.otf', '.woff', '.woff2', '.eot',
    # Database files
    '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb',
    # Virtual machines / disk images
    '.vmdk', '.vhd', '.vhdx', '.ova', '.ovf',
    # Temp / cache / lock
    '.tmp', '.temp', '.cache', '.lock', '.bak', '.swp', '.swo',
    '.DS_Store', '.Thumbs.db',
}

# Directory names to always skip when walking trees
SKIP_DIRECTORIES = {
    # Version control
    '.git', '.svn', '.hg', '.bzr',
    # Package managers / deps
    'node_modules', 'bower_components', 'vendor',
    'packages', '.nuget',
    # Python
    '__pycache__', '.venv', 'venv', 'env', '.env',
    'site-packages', 'dist-info', 'egg-info',
    # Build output
    'build', 'dist', 'out', 'output', 'bin', 'obj',
    'target', 'release', 'debug', 'Debug', 'Release',
    '.next', '.nuxt', '.svelte-kit',
    # IDE / editor
    '.idea', '.vscode', '.vs', '.eclipse',
    '__MACOSX',
    # OS / system
    '$RECYCLE.BIN', 'System Volume Information',
    'Windows', 'Program Files', 'Program Files (x86)',
}

# Apply any user customisations saved from the Auto Scan Configuration tab.
# This runs at import time so every subsequent scan/index uses the saved sets.
def _apply_saved_extension_config():
    global SUPPORTED_EXTENSIONS, SKIP_EXTENSIONS, SKIP_DIRECTORIES
    _cfg = Path.home() / '.rag_config.json'
    if not _cfg.exists():
        return
    try:
        import json as _json
        with open(_cfg, 'r') as _f:
            _c = _json.load(_f)
        if 'ext_supported_current' in _c:
            SUPPORTED_EXTENSIONS = set(_c['ext_supported_current'])
            SKIP_EXTENSIONS      = set(_c['ext_skipped_current'])
            SKIP_DIRECTORIES     = set(_c['dir_skipped_current'])
    except Exception:
        pass

_apply_saved_extension_config()

# ═══════════════════════════════════════════════════════════
# LICENSE KEY SYSTEM
# ═══════════════════════════════════════════════════════════

LICENSE_FILE = Path.home() / '.rag_license.key'
LICENSE_REQUIRED = False  # Set to True to require license key

def generate_machine_id():
    """Generate unique machine identifier"""
    import platform
    import hashlib
    
    # Combine machine-specific info
    machine_info = f"{platform.node()}{platform.machine()}{platform.system()}"
    
    # Create hash
    machine_hash = hashlib.sha256(machine_info.encode()).hexdigest()[:16]
    return machine_hash

def validate_license_key(license_key):
    """Validate license key format and checksum"""
    import hashlib
    
    if not license_key or len(license_key) != 29:  # Format: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
        return False
    
    parts = license_key.split('-')
    if len(parts) != 5:
        return False
    
    # Verify each part is 5 characters
    for part in parts:
        if len(part) != 5:
            return False
    
    # Verify checksum (last part)
    key_data = '-'.join(parts[:-1])
    checksum = hashlib.md5(key_data.encode()).hexdigest()[:5].upper()
    
    return parts[-1].upper() == checksum

def save_license_key(license_key):
    """Save validated license key"""
    try:
        with open(LICENSE_FILE, 'w') as f:
            f.write(license_key)
        return True
    except:
        return False

def load_license_key():
    """Load license key from file"""
    if LICENSE_FILE.exists():
        try:
            with open(LICENSE_FILE, 'r') as f:
                return f.read().strip()
        except:
            return None
    return None

def check_license():
    """Check if valid license exists"""
    if not LICENSE_REQUIRED:
        return True
    
    license_key = load_license_key()
    
    if not license_key:
        return False
    
    return validate_license_key(license_key)

def prompt_for_license():
    """Prompt user for license key"""
    print()
    print("=" * 70)
    print("LICENSE REQUIRED")
    print("=" * 70)
    print()
    print("This software requires a valid license key.")
    print()
    print("Machine ID:", generate_machine_id())
    print()
    
    license_key = input("Enter license key: ").strip()
    
    if validate_license_key(license_key):
        if save_license_key(license_key):
            print()
            print("✅ License key validated and saved!")
            print()
            return True
        else:
            print()
            print("❌ Could not save license key")
            print()
            return False
    else:
        print()
        print("❌ Invalid license key")
        print()
        return False

# ═══════════════════════════════════════════════════════════
# FILE LOADERS
# ═══════════════════════════════════════════════════════════

def load_text_file(filepath: str) -> str:
    """Load plain text files with various encodings"""
    encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
    
    for encoding in encodings:
        try:
            with open(filepath, 'r', encoding=encoding) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
        except Exception as e:
            print(f"⚠️  Error reading {filepath} with {encoding}: {e}")
            continue
    
    print(f"⚠️  Could not decode {filepath} with any encoding")
    return ""

def load_pdf(filepath: str) -> str:
    """Extract text from PDF"""
    text = ""
    try:
        with pdfplumber.open(filepath) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
    except Exception as e:
        print(f"⚠️  Error reading PDF {filepath}: {e}")
    return text

def load_docx(filepath: str) -> str:
    """Extract text from Word document"""
    try:
        doc = DocxDocument(filepath)
        paragraphs = [para.text for para in doc.paragraphs if para.text.strip()]
        return "\n".join(paragraphs)
    except Exception as e:
        print(f"⚠️  Error reading DOCX {filepath}: {e}")
        return ""

def clean_email_text(text: str) -> str:
    """Clean up email text by removing excessive whitespace"""
    if not text:
        return ""
    # Remove multiple newlines
    text = re.sub(r'\n\s*\n\s*\n', '\n\n', text)
    # Remove excessive spaces
    text = re.sub(r' +', ' ', text)
    return text.strip()

def load_eml(filepath: str) -> str:
    """Load .eml email file (Gmail, Outlook, Yahoo exports)"""
    try:
        with open(filepath, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        
        content_parts = []
        content_parts.append(f"Subject: {msg.get('Subject', '[No Subject]')}")
        content_parts.append(f"From: {msg.get('From', '[Unknown Sender]')}")
        content_parts.append(f"To: {msg.get('To', '[Unknown Recipient]')}")
        content_parts.append(f"Date: {msg.get('Date', '[Unknown Date]')}")
        
        cc = msg.get('Cc', '')
        if cc:
            content_parts.append(f"Cc: {cc}")
        
        content_parts.append("")  # Blank line before body
        
        # Extract body text
        body_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        content_parts.append(f"[Attachment: {filename}]")
                    continue
                
                # Get plain text
                if content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text = payload.decode('utf-8', errors='ignore')
                            break
                    except:
                        continue
                
                # Fall back to HTML if no plain text
                elif content_type == "text/html" and not body_text:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            html_text = payload.decode('utf-8', errors='ignore')
                            # Simple HTML stripping
                            body_text = re.sub(r'<[^>]+>', '', html_text)
                    except:
                        continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_text = payload.decode('utf-8', errors='ignore')
            except:
                body_text = str(msg.get_payload())
        
        if body_text:
            content_parts.append("Body:")
            content_parts.append(clean_email_text(body_text))
        
        return "\n".join(content_parts)
        
    except Exception as e:
        print(f"⚠️  Error reading EML {filepath}: {e}")
        return ""

def load_msg(filepath: str) -> str:
    """Load .msg Outlook email file"""
    try:
        import extract_msg
        
        msg = extract_msg.Message(filepath)
        
        content_parts = []
        content_parts.append(f"Subject: {msg.subject or '[No Subject]'}")
        content_parts.append(f"From: {msg.sender or '[Unknown Sender]'}")
        content_parts.append(f"To: {msg.to or '[Unknown Recipient]'}")
        content_parts.append(f"Date: {msg.date or '[Unknown Date]'}")
        
        if msg.cc:
            content_parts.append(f"Cc: {msg.cc}")
        
        content_parts.append("")
        
        if msg.body:
            content_parts.append("Body:")
            content_parts.append(clean_email_text(msg.body))
        
        # Note attachments
        if msg.attachments:
            for attachment in msg.attachments:
                filename = attachment.longFilename or attachment.shortFilename
                content_parts.append(f"[Attachment: {filename}]")
        
        msg.close()
        return "\n".join(content_parts)
        
    except ImportError:
        print(f"⚠️  extract-msg not installed. Run: pip install extract-msg")
        print(f"    Skipping {filepath}")
        return ""
    except Exception as e:
        print(f"⚠️  Error reading MSG {filepath}: {e}")
        return ""

def _extract_body_from_message(message) -> str:
    """
    Extract the best plain-text body from any email.message.Message object.
    Prefers text/plain, falls back to HTML-stripped text/html.
    Returns an empty string if nothing usable is found.
    """
    body_text = ""
    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            disposition   = str(part.get("Content-Disposition", ""))
            if "attachment" in disposition:
                continue
            if content_type == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text = payload.decode("utf-8", errors="ignore")
                        break
                except Exception:
                    continue
            elif content_type == "text/html" and not body_text:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body_text = re.sub(r"<[^>]+>", "",
                                           payload.decode("utf-8", errors="ignore"))
                except Exception:
                    continue
    else:
        try:
            payload = message.get_payload(decode=True)
            if payload:
                body_text = payload.decode("utf-8", errors="ignore")
        except Exception:
            body_text = str(message.get_payload() or "")
    return body_text


def _format_email_record(index: int, subject: str, from_: str,
                         to: str, date: str, cc: str,
                         body_text: str, attachments: list) -> str:
    """Build the human-readable text block stored in ChromaDB for one email."""
    parts = [
        f"[Email {index}]",
        f"Subject: {subject}",
        f"From:    {from_}",
        f"To:      {to}",
        f"Date:    {date}",
    ]
    if cc:
        parts.append(f"Cc:      {cc}")
    parts.append("")
    if body_text:
        parts.append("Body:")
        parts.append(clean_email_text(body_text))
    for att in attachments:
        parts.append(f"[Attachment: {att}]")
    return "\n".join(parts)


def iter_mbox_emails(filepath: str):
    """
    Generator: yield one dict per email in an .mbox archive.

    Each dict has keys:
      uid        – stable md5 string (from Message-ID or from+date+subject)
      index      – 1-based position in archive (for display only)
      text       – formatted text block ready for ChromaDB
      subject / from_ / date  – raw header strings (for progress display)
    """
    try:
        mbox  = mailbox.mbox(filepath)
        total = sum(1 for _ in mbox)          # count first (fast, reads keys only)
        mbox  = mailbox.mbox(filepath)        # re-open to iterate from start

        for i, message in enumerate(mbox, 1):
            subject = message.get("Subject", "[No Subject]")
            from_   = message.get("From",    "[Unknown Sender]")
            to_     = message.get("To",      "[Unknown Recipient]")
            date_   = message.get("Date",    "[Unknown Date]")
            cc_     = message.get("Cc",      "")
            msg_id  = message.get("Message-ID", "")

            uid = _make_message_uid(msg_id, (from_, date_, subject))
            body = _extract_body_from_message(message)

            attachments = []
            if message.is_multipart():
                for part in message.walk():
                    if "attachment" in str(part.get("Content-Disposition", "")):
                        fn = part.get_filename()
                        if fn:
                            attachments.append(fn)

            text = _format_email_record(i, subject, from_, to_, date_,
                                        cc_, body, attachments)
            yield {
                "uid":     uid,
                "index":   i,
                "total":   total,
                "text":    text,
                "subject": subject,
                "from_":   from_,
                "date":    date_,
            }
    except Exception as e:
        print(f"⚠️  Error reading MBOX {filepath}: {e}")


def _iter_mailbox_generic(mbox_obj, filepath: str, label: str):
    """
    Shared generator core for any mailbox.Mailbox subclass.
    Yields the same record dict as iter_mbox_emails().
    """
    try:
        keys  = list(mbox_obj.keys())
        total = len(keys)
        for i, key in enumerate(keys, 1):
            try:
                message = mbox_obj[key]
            except Exception:
                continue
            subject = message.get("Subject", "[No Subject]")
            from_   = message.get("From",    "[Unknown Sender]")
            to_     = message.get("To",      "[Unknown Recipient]")
            date_   = message.get("Date",    "[Unknown Date]")
            cc_     = message.get("Cc",      "")
            msg_id  = message.get("Message-ID", "")

            uid  = _make_message_uid(msg_id, (from_, date_, subject))
            body = _extract_body_from_message(message)

            attachments = []
            if message.is_multipart():
                for part in message.walk():
                    if "attachment" in str(part.get("Content-Disposition", "")):
                        fn = part.get_filename()
                        if fn:
                            attachments.append(fn)

            text = _format_email_record(i, subject, from_, to_, date_,
                                        cc_, body, attachments)
            yield {
                "uid":     uid,
                "index":   i,
                "total":   total,
                "text":    text,
                "subject": subject,
                "from_":   from_,
                "date":    date_,
            }
    except Exception as e:
        print(f"⚠️  Error reading {label} {filepath}: {e}")


def iter_maildir_emails(filepath: str):
    """
    Generator for Maildir format directories.

    Used by:
      • Thunderbird (optionally via Maildir plugin)
      • Postfix / Dovecot mail servers
      • Some Linux desktop mail clients (Evolution, KMail)

    A Maildir is a *directory* (not a file) containing three sub-folders:
    cur/, new/, tmp/.  Each email is an individual file inside those folders.
    """
    try:
        mdir = mailbox.Maildir(filepath, factory=None, create=False)
        yield from _iter_mailbox_generic(mdir, filepath, "Maildir")
    except Exception as e:
        print(f"⚠️  Error opening Maildir {filepath}: {e}")


def iter_babyl_emails(filepath: str):
    """
    Generator for GNU Babyl / RMAIL format (.rmail, .babyl).

    Used by:
      • GNU Emacs RMAIL
      • Very old Unix mail readers

    Rare today but still encountered in long-term archive exports.
    """
    try:
        bbl = mailbox.Babyl(filepath)
        yield from _iter_mailbox_generic(bbl, filepath, "Babyl")
    except Exception as e:
        print(f"⚠️  Error reading Babyl {filepath}: {e}")


def iter_mmdf_emails(filepath: str):
    """
    Generator for MMDF format (.mmdf).

    Used by:
      • SCO Unix / older SCO OpenServer systems
      • Some legacy corporate mail server exports
    """
    try:
        mmdf = mailbox.MMDF(filepath)
        yield from _iter_mailbox_generic(mmdf, filepath, "MMDF")
    except Exception as e:
        print(f"⚠️  Error reading MMDF {filepath}: {e}")


def iter_eml_folder_emails(filepath: str):
    """
    Generator for a *folder* full of individual .eml files.

    When filepath points to a directory containing .eml files (e.g. a Yahoo
    Mail or Outlook export folder, or an Apple Mail mailbox folder before
    conversion), this generator yields one record per .eml file found
    recursively, enabling the same incremental per-message deduplication used
    for .mbox archives.

    Supported export sources that produce folders of .eml files:
      • Yahoo Mail (exported via third-party tools like MailStore, ImapSync)
      • Outlook Web Access / Exchange (drag-export or 3rd-party tool export)
      • Windows Live Mail / Windows Mail
      • Postbox
    """
    import glob as _glob
    eml_files = sorted(_glob.glob(os.path.join(filepath, "**", "*.eml"),
                                  recursive=True))
    total = len(eml_files)
    if total == 0:
        print(f"   ℹ️  No .eml files found in folder: {filepath}")
        return

    for i, eml_path in enumerate(eml_files, 1):
        try:
            with open(eml_path, "rb") as f:
                from email.parser import BytesParser
                from email import policy as _policy
                msg = BytesParser(policy=_policy.default).parse(f)

            subject = str(msg.get("Subject", "[No Subject]"))
            from_   = str(msg.get("From",    "[Unknown Sender]"))
            to_     = str(msg.get("To",      "[Unknown Recipient]"))
            date_   = str(msg.get("Date",    "[Unknown Date]"))
            cc_     = str(msg.get("Cc",      ""))
            msg_id  = str(msg.get("Message-ID", ""))

            uid  = _make_message_uid(msg_id, (from_, date_, subject))
            body = _extract_body_from_message(msg)

            attachments = []
            if msg.is_multipart():
                for part in msg.walk():
                    if "attachment" in str(part.get("Content-Disposition", "")):
                        fn = part.get_filename()
                        if fn:
                            attachments.append(fn)

            text = _format_email_record(i, subject, from_, to_, date_,
                                        cc_, body, attachments)
            yield {
                "uid":     uid,
                "index":   i,
                "total":   total,
                "text":    text,
                "subject": subject,
                "from_":   from_,
                "date":    date_,
            }
        except Exception as e:
            print(f"   ⚠️  Skipping {os.path.basename(eml_path)}: {e}")


def load_mbox(filepath: str) -> str:
    """
    Legacy single-blob loader kept for backwards compatibility.
    Only used when index_file_list() calls load_file() on a .mbox directly
    (i.e. non-smart-scan / index_directory path).
    For the normal GUI path, index_email_archive() is used instead.
    """
    try:
        all_emails = []
        for rec in iter_mbox_emails(filepath):
            all_emails.append(rec["text"])
        return ("\n\n" + "=" * 60 + "\n\n").join(all_emails) if all_emails else ""
    except Exception as e:
        print(f"⚠️  Error reading MBOX {filepath}: {e}")
        return ""

def _load_archive_as_blob(filepath: str) -> str:
    """
    Legacy single-blob fallback for all archive types.
    Routes to the correct iterator based on extension.
    Used by load_file() (non-smart-scan / CLI path only).
    The GUI smart-scan path always uses index_email_archive() instead.
    """
    ext = Path(filepath).suffix.lower()
    gen_map = {
        '.mbox':  iter_mbox_emails,
        '.rmail': iter_babyl_emails,
        '.babyl': iter_babyl_emails,
        '.mmdf':  iter_mmdf_emails,
    }
    gen_fn = gen_map.get(ext)
    if gen_fn is None:
        return ""
    try:
        texts = [rec["text"] for rec in gen_fn(filepath)]
        return ("\n\n" + "=" * 60 + "\n\n").join(texts) if texts else ""
    except Exception as e:
        print(f"⚠️  Error reading archive {filepath}: {e}")
        return ""
    """
    Load .emlx Apple Mail native format
    
    Format:
    - Line 1: Message size in bytes
    - Line 2+: Standard email message
    - May include Apple plist XML at end
    """
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
        
        # First line is byte count - split on first newline
        parts = content.split(b'\n', 1)
        
        if len(parts) < 2:
            print(f"⚠️  Invalid .emlx format: {filepath}")
            return ""
        
        # Skip byte count line, get email content
        email_content = parts[1]
        
        # Some .emlx files have plist XML at end - remove it
        if b'<?xml' in email_content:
            xml_start = email_content.find(b'<?xml')
            email_content = email_content[:xml_start]
        
        # Parse as standard email message
        msg = BytesParser(policy=policy.default).parsebytes(email_content)
        
        # Extract content (same as .eml)
        content_parts = []
        content_parts.append(f"Subject: {msg.get('Subject', '[No Subject]')}")
        content_parts.append(f"From: {msg.get('From', '[Unknown Sender]')}")
        content_parts.append(f"To: {msg.get('To', '[Unknown Recipient]')}")
        content_parts.append(f"Date: {msg.get('Date', '[Unknown Date]')}")
        
        cc = msg.get('Cc', '')
        if cc:
            content_parts.append(f"Cc: {cc}")
        
        content_parts.append("")
        
        # Extract body text
        body_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    filename = part.get_filename()
                    if filename:
                        content_parts.append(f"[Attachment: {filename}]")
                    continue
                
                # Get plain text
                if content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text = payload.decode('utf-8', errors='ignore')
                            break
                    except:
                        continue
                
                # Fall back to HTML
                elif content_type == "text/html" and not body_text:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            html_text = payload.decode('utf-8', errors='ignore')
                            # Simple HTML stripping
                            body_text = re.sub(r'<[^>]+>', '', html_text)
                    except:
                        continue
        else:
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    body_text = payload.decode('utf-8', errors='ignore')
            except:
                body_text = str(msg.get_payload())
        
        if body_text:
            content_parts.append("Body:")
            content_parts.append(clean_email_text(body_text))
        
        return "\n".join(content_parts)
        
    except Exception as e:
        print(f"⚠️  Error reading EMLX {filepath}: {e}")
        return ""

def load_file(filepath: str) -> Optional[Dict[str, str]]:
    """Load any supported file type"""
    filepath = normalise_path(filepath)   # ensure consistent path separators
    ext = Path(filepath).suffix.lower()

    if ext not in SUPPORTED_EXTENSIONS:
        return None
    
    # Determine loader
    if ext == '.pdf':
        content = load_pdf(filepath)
    elif ext == '.docx':
        content = load_docx(filepath)
    elif ext == '.eml':
        content = load_eml(filepath)
    elif ext == '.msg':
        content = load_msg(filepath)
    elif ext in ('.mbox', '.rmail', '.babyl', '.mmdf'):
        # Legacy blob fallback — normal GUI path uses index_email_archive() instead
        content = _load_archive_as_blob(filepath)
    elif ext == '.emlx':
        content = load_emlx(filepath)
    else:
        content = load_text_file(filepath)
    
    if not content or not content.strip():
        return None
    
    return {
        'filepath': filepath,
        'filename': Path(filepath).name,
        'content': content,
        'extension': ext,
        'size_bytes': len(content),
        'word_count': len(content.split())
    }

# ═══════════════════════════════════════════════════════════
# TEXT CHUNKING
# ═══════════════════════════════════════════════════════════

def chunk_text(text: str, chunk_size: int = CHUNK_SIZE, 
               overlap: int = CHUNK_OVERLAP) -> List[str]:
    """
    Split text into overlapping chunks
    
    Args:
        text: Input text to chunk
        chunk_size: Number of words per chunk
        overlap: Number of words to overlap between chunks
    
    Returns:
        List of text chunks
    """
    words = text.split()
    chunks = []
    
    if len(words) == 0:
        return chunks
    
    # Guard against zero or negative step (e.g. overlap >= chunk_size)
    step = chunk_size - overlap
    if step <= 0:
        step = chunk_size  # fallback: no overlap
    
    for i in range(0, len(words), step):
        chunk = ' '.join(words[i:i + chunk_size])
        if len(chunk.strip()) > 0:
            chunks.append(chunk)
        
        # Prevent infinite loop
        if i + chunk_size >= len(words):
            break
    
    return chunks

# ═══════════════════════════════════════════════════════════
# GPU DETECTION
# ═══════════════════════════════════════════════════════════

def detect_gpu():
    """
    Detect available GPU hardware and return a diagnostic dict with:
      - 'embedding_device': best device for sentence-transformers ('cuda','mps','cpu')
      - 'cuda_available': bool
      - 'cuda_device_name': GPU name string or None
      - 'cuda_vram_gb': total VRAM in GB or None
      - 'mps_available': bool (Apple Silicon)
      - 'ollama_gpu_note': human-readable note about what Ollama is currently using
    """
    result = {
        'embedding_device': 'cpu',
        'cuda_available': False,
        'cuda_device_name': None,
        'cuda_vram_gb': None,
        'mps_available': False,
        'ollama_gpu_note': '',
    }

    try:
        import torch
        if torch.cuda.is_available():
            result['cuda_available'] = True
            result['embedding_device'] = 'cuda'
            try:
                result['cuda_device_name'] = torch.cuda.get_device_name(0)
                vram = torch.cuda.get_device_properties(0).total_memory
                result['cuda_vram_gb'] = round(vram / (1024 ** 3), 1)
            except Exception:
                pass
        elif hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
            result['mps_available'] = True
            result['embedding_device'] = 'mps'
    except ImportError:
        pass  # torch not installed — embedding model will use CPU

    # Check what Ollama is actually using right now via /api/ps
    try:
        resp = requests.get(f"{OLLAMA_URL}/api/ps", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            models = data.get('models', [])
            if models:
                size_vram = models[0].get('size_vram', 0)
                size_total = models[0].get('size', 0)
                if size_vram and size_total:
                    pct = round(size_vram / size_total * 100)
                    result['ollama_gpu_note'] = (
                        f"{pct}% of model in VRAM "
                        f"({round(size_vram / 1024**3, 1)} GB / "
                        f"{round(size_total / 1024**3, 1)} GB total)"
                    )
                elif size_vram == 0 and size_total > 0:
                    result['ollama_gpu_note'] = "Running on CPU only (0 bytes in VRAM)"
                else:
                    result['ollama_gpu_note'] = "Model not currently loaded"
            else:
                result['ollama_gpu_note'] = "No model currently loaded in Ollama"
    except Exception:
        result['ollama_gpu_note'] = "Could not connect to Ollama"

    return result


def get_best_embedding_device() -> str:
    """Return the best available torch device string for the embedding model.
    Returns 'cuda', 'mps', or 'cpu'. Fast — only imports torch if available."""
    try:
        import torch
        if torch.cuda.is_available():
            return 'cuda'
        if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
            return 'mps'
    except ImportError:
        pass
    return 'cpu'


# ═══════════════════════════════════════════════════════════
# VECTOR DATABASE
# ═══════════════════════════════════════════════════════════

def get_chroma_client():
    """
    Initialize ChromaDB client with the sentence-transformer embedding model.

    The client and embedding function are cached at module level after the
    first call so that the ~3-8 second model-load cost is only paid once per
    session regardless of how many times this function is called (queries,
    indexing, stats, updates, etc.).

    The "Loading embedding model" message is suppressed on cache hits so the
    GUI output box stays clean.
    """
    global _chroma_client_cache, _embedding_func_cache

    if _chroma_client_cache is not None and _embedding_func_cache is not None:
        # Return cached instances — no disk I/O or model loading
        return _chroma_client_cache, _embedding_func_cache

    # First call — load everything and cache it
    if not GUI_MODE:
        print(f"🔧 Initializing ChromaDB at {CHROMA_DB_PATH}...")

    client = chromadb.PersistentClient(path=CHROMA_DB_PATH)

    # Auto-detect best device for the embedding model (CUDA > MPS > CPU)
    device = get_best_embedding_device()

    if not GUI_MODE:
        print(f"🔧 Loading embedding model: {EMBEDDING_MODEL} (device: {device})")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        embedding_func = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name=EMBEDDING_MODEL,
            device=device
        )

    _chroma_client_cache = client
    _embedding_func_cache = embedding_func

    return client, embedding_func

def create_or_get_collection(client, embedding_func):
    """Create or retrieve the document collection"""
    try:
        collection = client.get_collection(
            name=COLLECTION_NAME,
            embedding_function=embedding_func
        )
        count = collection.count()
        print(f"📂 Using existing collection: {COLLECTION_NAME} ({count} chunks)")
    except:
        collection = client.create_collection(
            name=COLLECTION_NAME,
            embedding_function=embedding_func,
            metadata={
                "description": "AI Prowler document store",
                "created": datetime.now().isoformat()
            }
        )
        print(f"✨ Created new collection: {COLLECTION_NAME}")
    
    return collection

# ═══════════════════════════════════════════════════════════
# INDEXING
# ═══════════════════════════════════════════════════════════

def scan_directory(directory: str, recursive: bool = True) -> dict:
    """
    Scan a directory tree and classify every file without indexing anything.
    Also handles the case where 'directory' is actually a single file path —
    Browse Files lets users queue individual files directly, and os.walk
    silently returns nothing when given a file path instead of a directory.

    Returns a dict:
      {
        'to_index':    [(filepath, ext), ...],  # supported, will be indexed
        'skipped_bin': [(filepath, ext), ...],  # in SKIP_EXTENSIONS
        'skipped_dir': [dirname, ...],          # directories pruned
        'unsupported': [(filepath, ext), ...],  # unknown extension
        'total_seen':  int,
      }
    """
    result = {
        'to_index':    [],
        'skipped_bin': [],
        'skipped_dir': [],
        'unsupported': [],
        'total_seen':  0,
    }

    if not os.path.exists(directory):
        return result

    # ── Single file queued directly (e.g. via Browse Files) ──────────────────
    if os.path.isfile(directory):
        fp   = normalise_path(directory)
        ext  = os.path.splitext(fp)[1].lower()
        result['total_seen'] = 1
        if ext in SKIP_EXTENSIONS:
            result['skipped_bin'].append((fp, ext))
        elif ext in SUPPORTED_EXTENSIONS:
            result['to_index'].append((fp, ext))
        else:
            result['unsupported'].append((fp, ext))
        return result

    # ── Directory path ────────────────────────────────────────────────────────
    if recursive:
        for root, dirs, files in os.walk(directory):
            # Prune and record skipped directories
            pruned = [d for d in dirs
                      if d.startswith('.') or d in SKIP_DIRECTORIES]
            result['skipped_dir'].extend(pruned)
            dirs[:] = [d for d in dirs
                       if not d.startswith('.') and d not in SKIP_DIRECTORIES]

            for fname in files:
                if fname.startswith('.'):
                    continue
                result['total_seen'] += 1
                fp  = os.path.join(root, fname)
                ext = os.path.splitext(fname)[1].lower()

                if ext in SKIP_EXTENSIONS:
                    result['skipped_bin'].append((fp, ext))
                elif ext in SUPPORTED_EXTENSIONS:
                    result['to_index'].append((fp, ext))
                else:
                    result['unsupported'].append((fp, ext))
    else:
        for fname in os.listdir(directory):
            fp = os.path.join(directory, fname)
            if not os.path.isfile(fp) or fname.startswith('.'):
                continue
            result['total_seen'] += 1
            ext = os.path.splitext(fname)[1].lower()
            if ext in SKIP_EXTENSIONS:
                result['skipped_bin'].append((fp, ext))
            elif ext in SUPPORTED_EXTENSIONS:
                result['to_index'].append((fp, ext))
            else:
                result['unsupported'].append((fp, ext))

    return result


def index_file_list(file_paths: list, label: str = "",
                    stop_event=None, pause_event=None,
                    start_from: int = 0) -> dict:
    """
    Index a specific pre-built list of file paths.

    Email archive files (.mbox) are handled specially: they are routed to
    index_email_archive() which processes them message-by-message, providing
    per-message progress, near-instant stop response, and incremental indexing
    (only new/changed messages are indexed; removed ones are cleaned up).

    Args:
        file_paths:  List of absolute file paths to index
        label:       Optional label for progress messages (e.g. directory name)
        stop_event:  threading.Event — if set, stop after current file/message
        pause_event: threading.Event — if set, block until cleared
        start_from:  File index to resume from (skip already-indexed files)

    Returns dict with keys: processed, skipped, chunks, words, stopped_at
      stopped_at = 1-based index of next unprocessed file (0 if completed)
    """
    import time as _time
    client, embedding_func = get_chroma_client()
    collection = create_or_get_collection(client, embedding_func)

    total     = len(file_paths)
    processed = skipped = total_chunks = total_words = 0
    stopped_at = 0

    prefix = f"[{label}] " if label else ""

    for i, filepath in enumerate(file_paths, 1):
        # Skip files already processed before a resume point
        if i <= start_from:
            continue

        # Pause: block here until unpaused
        if pause_event and pause_event.is_set():
            print(f"         ⏸  Paused…")
            while pause_event.is_set():
                _time.sleep(0.2)
                if stop_event and stop_event.is_set():
                    break
            if not (stop_event and stop_event.is_set()):
                print(f"         ▶  Resumed")

        # Stop: record position and exit cleanly
        if stop_event and stop_event.is_set():
            stopped_at = i
            print(f"\n⏹  Stopped at file {i}/{total} — "
                  f"run Resume to continue from here.")
            break

        filepath = normalise_path(filepath)
        ext      = Path(filepath).suffix.lower()
        progress = f"[{i}/{total}]"

        # ── Email archive — use per-message incremental indexer ────────────────
        if ext in EMAIL_ARCHIVE_EXTENSIONS:
            print(f"{prefix}{progress} 📬 {os.path.basename(filepath)}  "
                  f"[email archive — incremental]")
            arc_stats = index_email_archive(
                filepath,
                stop_event=stop_event,
                pause_event=pause_event,
            )
            processed    += arc_stats["processed"]
            skipped      += arc_stats["skipped"]
            total_chunks += arc_stats["chunks"]
            total_words  += arc_stats["words"]

            if arc_stats["stopped_at"]:
                # Archive was stopped mid-way — propagate stop to outer loop
                stopped_at = i
                break
            continue

        # ── All other file types — normal single-file loader ───────────────────
        file_data = load_file(filepath)
        if not file_data:
            skipped += 1
            continue

        print(f"{prefix}{progress} {os.path.basename(filepath)}  "
              f"({file_data['word_count']} words)")

        chunks = chunk_text(file_data['content'], CHUNK_SIZE, CHUNK_OVERLAP)
        if not chunks:
            print(f"         ⚠️  Empty — skipping")
            skipped += 1
            continue

        ids = [f"{filepath}__chunk_{j}" for j in range(len(chunks))]
        metadatas = [{
            'filepath':     filepath,
            'filename':     file_data['filename'],
            'chunk_index':  j,
            'total_chunks': len(chunks),
            'extension':    file_data['extension'],
            'indexed_date': datetime.now().isoformat()
        } for j in range(len(chunks))]

        try:
            collection.delete(where={"filepath": filepath})
        except Exception:
            pass

        try:
            collection.add(ids=ids, documents=chunks, metadatas=metadatas)
            processed    += 1
            total_chunks += len(chunks)
            total_words  += file_data['word_count']
            print(f"         ✅ {len(chunks)} chunks added")
        except Exception as e:
            print(f"         ❌ Error: {e}")
            skipped += 1

    return {
        'processed':  processed,
        'skipped':    skipped,
        'chunks':     total_chunks,
        'words':      total_words,
        'stopped_at': stopped_at,
    }


def index_email_archive(filepath: str,
                        stop_event=None,
                        pause_event=None) -> dict:
    """
    Incrementally index a multi-message email archive file.

    Supported archive types (routed here via index_file_list):
      .mbox   — Unix mbox format: Gmail Takeout, Thunderbird, Apple Mail
                export, iCloud Mail (via Apple Mail), Yahoo Mail (via tools)
      .rmail  — GNU Emacs RMAIL / Babyl format
      .babyl  — GNU Babyl (alternate extension for the same format)
      .mmdf   — MMDF format (legacy Unix / SCO mail servers)

    For folders of .eml files (Yahoo, Outlook drag-export, Windows Live Mail)
    use index_eml_folder() which wraps iter_eml_folder_emails() — these are
    handled separately because the "file" is a directory, not a single file.

    How incremental indexing works
    ───────────────────────────────
    Each message is identified by a stable UID derived from its Message-ID
    header (an RFC 5322 globally-unique string).  When a fallback is needed
    (message has no Message-ID) we hash From + Date + Subject instead.

    On every run we compare the set of UIDs in the archive against the set of
    UIDs already stored in ~/.rag_email_index.json for this file path:

      • NEW uid (in archive, not in index)    → index the message
      • REMOVED uid (in index, not in archive) → delete its chunks from ChromaDB
      • UNCHANGED uid (in both)               → skip entirely

    This means a 100,000-email archive that gains 50 new messages this week
    only processes those 50 — not the entire archive.

    Stop / pause
    ────────────
    The stop_event is checked after EVERY message so response is near-instant
    even for giant archives.  Pause works the same way.

    Returns dict with: processed, skipped, removed, chunks, words, stopped_at
      stopped_at = 1-based email index of next unprocessed message (0 = done)
    """
    import time as _time

    filepath_norm = normalise_path(filepath)
    ext           = Path(filepath).suffix.lower()
    fname         = Path(filepath).name

    client, embedding_func = get_chroma_client()
    collection             = create_or_get_collection(client, embedding_func)

    # ── Load existing email index for this file ────────────────────────────────
    email_db     = load_email_index()
    file_key     = filepath_norm
    known_uids   = set(email_db.get(file_key, {}).get("uids", []))
    new_uids     = set()      # UIDs seen in *this* run of the archive

    processed = skipped = removed = total_chunks = total_words = 0
    stopped_at = 0

    # ── Determine generator based on file type ─────────────────────────────────
    gen_map = {
        '.mbox':  iter_mbox_emails,    # Gmail Takeout, Thunderbird, Apple Mail, Yahoo
        '.rmail': iter_babyl_emails,   # GNU Emacs RMAIL
        '.babyl': iter_babyl_emails,   # GNU Babyl (alternate extension)
        '.mmdf':  iter_mmdf_emails,    # Legacy Unix MMDF
    }
    gen_fn = gen_map.get(ext)
    if gen_fn is None:
        print(f"⚠️  Unsupported archive type for incremental indexing: {ext}")
        return {"processed": 0, "skipped": 0, "removed": 0,
                "chunks": 0, "words": 0, "stopped_at": 0}
    email_gen = gen_fn(filepath)

    # ── Pass 1: iterate archive, index new messages, collect seen UIDs ─────────
    print(f"📬 Incremental email indexing: {fname}")

    for rec in email_gen:
        i     = rec["index"]
        total = rec["total"]
        uid   = rec["uid"]

        new_uids.add(uid)

        # ── Pause ──────────────────────────────────────────────────────────────
        if pause_event and pause_event.is_set():
            print(f"         ⏸  Paused…")
            while pause_event.is_set():
                _time.sleep(0.2)
                if stop_event and stop_event.is_set():
                    break
            if not (stop_event and stop_event.is_set()):
                print(f"         ▶  Resumed")

        # ── Stop ───────────────────────────────────────────────────────────────
        if stop_event and stop_event.is_set():
            stopped_at = i
            print(f"\n⏹  Stopped at email {i}/{total} — "
                  f"run Resume to continue from here.")
            break

        # ── Already indexed? ───────────────────────────────────────────────────
        if uid in known_uids:
            skipped += 1
            continue

        # ── New message — index it ─────────────────────────────────────────────
        text  = rec["text"]
        words = len(text.split())

        print(f"   [{i}/{total}] NEW  {rec['subject'][:60]}  ({words} words)")

        chunks = chunk_text(text, CHUNK_SIZE, CHUNK_OVERLAP)
        if not chunks:
            skipped += 1
            continue

        # Use uid-based chunk IDs so they are stable across re-runs
        ids       = [f"{filepath_norm}__email_{uid}__chunk_{j}"
                     for j in range(len(chunks))]
        metadatas = [{
            "filepath":      filepath_norm,
            "filename":      fname,
            "email_uid":     uid,
            "chunk_index":   j,
            "total_chunks":  len(chunks),
            "extension":     ext,
            "indexed_date":  datetime.now().isoformat(),
        } for j in range(len(chunks))]

        try:
            collection.add(ids=ids, documents=chunks, metadatas=metadatas)
            processed    += 1
            total_chunks += len(chunks)
            total_words  += words
            print(f"         ✅ {len(chunks)} chunks added")
        except Exception as e:
            print(f"         ❌ Error: {e}")
            skipped += 1

    # ── Pass 2: remove deleted messages (only when not stopped mid-way) ────────
    if not stopped_at:
        deleted_uids = known_uids - new_uids
        if deleted_uids:
            print(f"\n🗑  Removing {len(deleted_uids)} deleted email(s) from index…")
            for uid in deleted_uids:
                try:
                    collection.delete(where={"email_uid": uid})
                    removed += 1
                except Exception as e:
                    print(f"   ⚠️  Could not remove uid {uid[:8]}…: {e}")

        # ── Persist updated email index ────────────────────────────────────────
        merged_uids = (known_uids | new_uids) - (known_uids - new_uids)
        email_db[file_key] = {
            "uids":       list(merged_uids),
            "last_indexed": datetime.now().isoformat(),
            "message_count": len(merged_uids),
        }
        save_email_index(email_db)

        print(f"\n   📬 Email index: {len(merged_uids):,} messages tracked, "
              f"{processed} new, {removed} removed, {skipped} unchanged")
    else:
        # Partial run — persist only the UIDs we successfully processed so far
        merged_uids = known_uids | new_uids
        email_db[file_key] = {
            "uids":       list(merged_uids),
            "last_indexed": datetime.now().isoformat(),
            "message_count": len(merged_uids),
        }
        save_email_index(email_db)

    return {
        "processed":  processed,
        "skipped":    skipped,
        "removed":    removed,
        "chunks":     total_chunks,
        "words":      total_words,
        "stopped_at": stopped_at,
    }


def index_directory(directory: str, recursive: bool = True, quiet: bool = False):
    """
    Index all files in a directory
    
    Args:
        directory: Path to directory to index
        recursive: Whether to search subdirectories
        quiet: Whether to suppress verbose output
    """
    if not quiet:
        print(f"\n{'='*60}")
        print(f"🔍 INDEXING DIRECTORY")
        print(f"{'='*60}")
        print(f"📁 Path: {directory}")
        print(f"🔄 Recursive: {recursive}")
        print(f"{'='*60}\n")
    
    if not os.path.exists(directory):
        print(f"❌ Directory not found: {directory}")
        return
    
    # Initialize database
    client, embedding_func = get_chroma_client()
    collection = create_or_get_collection(client, embedding_func)
    
    # Find all files — skip binaries, executables and known-useless dirs
    all_files = []
    if recursive:
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs
                       if not d.startswith('.')
                       and d not in SKIP_DIRECTORIES]
            for file in files:
                if not file.startswith('.'):
                    ext = os.path.splitext(file)[1].lower()
                    if ext not in SKIP_EXTENSIONS:
                        all_files.append(normalise_path(os.path.join(root, file)))
    else:
        for f in os.listdir(directory):
            if not f.startswith('.'):
                ext = os.path.splitext(f)[1].lower()
                if ext not in SKIP_EXTENSIONS:
                    fp = normalise_path(os.path.join(directory, f))
                    if os.path.isfile(fp):
                        all_files.append(fp)
    
    print(f"📊 Found {len(all_files)} files\n")
    
    # Process each file
    total_chunks = 0
    processed_files = 0
    skipped_files = 0
    total_words = 0
    
    for i, filepath in enumerate(all_files, 1):
        # Progress indicator
        progress = f"[{i}/{len(all_files)}]"
        
        # Load file
        file_data = load_file(filepath)
        if not file_data:
            skipped_files += 1
            continue
        
        print(f"{progress} Processing: {filepath}")
        print(f"         Size: {file_data['word_count']} words")
        
        # Chunk content
        chunks = chunk_text(file_data['content'], CHUNK_SIZE, CHUNK_OVERLAP)
        
        if len(chunks) == 0:
            print(f"         ⚠️  Empty file, skipping\n")
            skipped_files += 1
            continue
        
        # Prepare for database
        ids = [f"{filepath}__chunk_{j}" for j in range(len(chunks))]
        metadatas = [{
            'filepath': filepath,
            'filename': file_data['filename'],
            'chunk_index': j,
            'total_chunks': len(chunks),
            'extension': file_data['extension'],
            'indexed_date': datetime.now().isoformat()
        } for j in range(len(chunks))]
        
        # Remove any existing chunks for this file before re-adding
        # This prevents ghost chunks from shorter re-processed files and
        # duplicate accumulation from repeated indexing of the same directory
        try:
            collection.delete(where={"filepath": filepath})
        except Exception:
            pass  # Collection may not have this file yet — that's fine
        
        # Add to database
        try:
            collection.add(
                ids=ids,
                documents=chunks,
                metadatas=metadatas
            )
            
            processed_files += 1
            total_chunks += len(chunks)
            total_words += file_data['word_count']
            if not quiet:
                print(f"         ✅ Added {len(chunks)} chunks\n")
            
        except Exception as e:
            print(f"         ❌ Error adding to database: {e}\n")
            skipped_files += 1
    
    # Summary
    if not quiet:
        print(f"\n{'='*60}")
        print(f"✨ INDEXING COMPLETE")
        print(f"{'='*60}")
        print(f"📊 Files processed: {processed_files}")
        print(f"📊 Files skipped: {skipped_files}")
        print(f"📊 Total chunks: {total_chunks}")
        print(f"📊 Total words: {total_words:,}")
        print(f"💾 Database: {CHROMA_DB_PATH}")
        print(f"{'='*60}\n")
    
    # Automatically scan after indexing to establish tracking baseline
    if not quiet:
        print("🔍 Setting up file tracking...\n")
    
    try:
        result = scan_directory_for_changes(directory, recursive)
        if result:
            results_scan, tracking_db, dir_key = result

            # Populate the file-timestamp baseline so Update All correctly
            # treats all just-indexed files as UNCHANGED on the next run,
            # and only re-indexes genuinely new or modified files.
            tracking_db[dir_key]['files'] = {}
            for file_info in results_scan['all_files']:
                tracking_db[dir_key]['files'][normalise_path(file_info['path'])] = {
                    'modified':       file_info['modified'],
                    'modified_human': file_info['modified_human'],
                    'size':           file_info['size'],
                }
            tracking_db[dir_key]['last_scan'] = results_scan['scan_time']

            if save_tracking_database(tracking_db):
                if not quiet:
                    print(f"✅ File tracking enabled for this directory")
                    print(f"   Use 'rag update {directory}' to keep index current\n")

                # Add to auto-update list
                is_new = add_to_auto_update_list(directory)

                if is_new and not quiet:
                    print(f"✅ Added to auto-update list")

                    # Show script location
                    if sys.platform == 'win32':
                        script_path = Path.home() / 'rag_auto_update.bat'
                    else:
                        script_path = Path.home() / 'rag_auto_update.sh'

                    if script_path.exists():
                        print(f"📝 Auto-update script regenerated: {script_path}")
                    print()
            else:
                if not quiet:
                    print(f"⚠️  Could not enable file tracking\n")
    except Exception as e:
        if not quiet:
            print(f"⚠️  File tracking setup failed: {e}\n")

# ═══════════════════════════════════════════════════════════
# RETRIEVAL
# ═══════════════════════════════════════════════════════════

def search_documents(query: str, n_results: int = 3) -> List[Dict]:
    """
    Search for relevant document chunks
    
    Args:
        query: Search query
        n_results: Number of results to return
    
    Returns:
        List of matching chunks with metadata
    """
    client, embedding_func = get_chroma_client()
    
    try:
        collection = client.get_collection(
            name=COLLECTION_NAME,
            embedding_function=embedding_func
        )
    except:
        print("❌ No indexed documents found. Run 'index' command first.")
        return []
    
    # Search
    results = collection.query(
        query_texts=[query],
        n_results=n_results
    )
    
    # Format results
    chunks = []
    for i in range(len(results['documents'][0])):
        chunks.append({
            'content': results['documents'][0][i],
            'metadata': results['metadatas'][0][i],
            'distance': results['distances'][0][i],
            'similarity': 1 - results['distances'][0][i]  # Convert distance to similarity
        })
    
    return chunks

# ═══════════════════════════════════════════════════════════
# LLM QUERY
# ═══════════════════════════════════════════════════════════

def check_ollama_available() -> bool:
    """Check if Ollama is running"""
    try:
        response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=20)
        return response.status_code == 200
    except:
        return False


def is_model_loaded(num_ctx: int = None) -> bool:
    """
    Check /api/ps to see if the model is already loaded in Ollama RAM at the
    correct num_ctx.  If it is, prewarm_ollama() can skip entirely — sending
    a prewarm request when Ollama is already busy (e.g. the user clicked Ask
    Question right after changing chunks) blocks the real query for minutes.

    Returns True if model is loaded AND (num_ctx matches or num_ctx is None).
    """
    try:
        ctx    = num_ctx if num_ctx is not None else get_model_num_ctx(OLLAMA_MODEL)
        resp   = requests.get(f"{OLLAMA_URL}/api/ps", timeout=5)
        if resp.status_code != 200:
            return False
        models = resp.json().get('models', [])
        for m in models:
            name = m.get('name', '') or m.get('model', '')
            # Strip tag for fuzzy match (llama3.2:1b == llama3.2:1b)
            if OLLAMA_MODEL.split(':')[0] in name:
                loaded_ctx = (m.get('model_info', {})
                              .get('llama.context_length')
                              or m.get('details', {}).get('context_length')
                              or ctx)   # fallback: assume match
                if int(loaded_ctx) >= ctx:
                    print(f"✅ is_model_loaded: {name} already in RAM "
                          f"(ctx={loaded_ctx} >= needed={ctx}) — skipping prewarm")
                    return True
        return False
    except Exception as e:
        print(f"⚠️  is_model_loaded check failed: {e}")
        return False

def prewarm_ollama(num_ctx: int = None) -> bool:
    """
    Load the current model into Ollama's memory without generating any output.

    Sends an empty prompt with num_predict=0 so Ollama loads model weights into
    RAM/VRAM immediately and holds them for 30 minutes (keep_alive=30m).

    CRITICAL: num_ctx here MUST match every subsequent query_ollama() call.
    If they differ Ollama silently reloads the model, adding 5-8 min latency.

    Args:
        num_ctx: Context window size to load the model with.  Pass the value
                 returned by safe_num_ctx_for_prompt() when the user has chosen
                 a large chunk count (10, 15, 20) so the model is pre-loaded
                 at the right size.  If None, uses the model's default.

    Returns True if loaded successfully, False otherwise.
    """
    if not check_ollama_available():
        return False
    try:
        ctx = num_ctx if num_ctx is not None else get_model_num_ctx(OLLAMA_MODEL)
        # Skip the blocking /api/generate call if model is already in RAM at
        # the right ctx.  This prevents the prewarm from queueing ahead of a
        # real query in Ollama and causing a multi-minute wait.
        if is_model_loaded(ctx):
            return True
        print(f"⚡ prewarm_ollama: loading {OLLAMA_MODEL}  num_ctx={ctx}  gpu={GPU_LAYERS}")
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={
                'model':      OLLAMA_MODEL,
                'prompt':     '',
                'stream':     False,
                'keep_alive': '30m',
                'options': {
                    'num_predict': 0,
                    'num_ctx':     ctx,   # ← must match every query call
                    'num_gpu':     GPU_LAYERS,
                }
            },
            timeout=120
        )
        if resp.status_code == 200:
            print(f"✅ prewarm_ollama: ready  (model={OLLAMA_MODEL}  num_ctx={ctx})")
            return True
        print(f"⚠️  prewarm_ollama: HTTP {resp.status_code}")
        return False
    except Exception as e:
        print(f"⚠️  prewarm_ollama failed: {e}")
        return False


def prewarm_embeddings() -> bool:
    """
    Load the sentence-transformer embedding model into memory.

    Calls get_chroma_client() which triggers the one-time load of
    all-MiniLM-L6-v2 and caches the result. After this returns, all
    subsequent calls to get_chroma_client() (searches, indexing, stats)
    return instantly from cache with no model loading overhead.

    Returns True on success, False if loading failed.
    Safe to call from a background thread at any time.
    """
    try:
        get_chroma_client()
        return True
    except Exception:
        return False


def invalidate_chroma_cache():
    """
    Clear the cached ChromaDB client and embedding model.

    Call this when EMBEDDING_MODEL changes so the next get_chroma_client()
    call reloads with the new model instead of using the stale cached one.
    """
    global _chroma_client_cache, _embedding_func_cache
    _chroma_client_cache = None
    _embedding_func_cache = None

def query_ollama(prompt: str, max_tokens: int = 2000, images_b64: list = None) -> str:
    """
    Send prompt to Ollama and stream tokens back in real time.

    Key design points
    -----------------
    * stream=True  — tokens appear word-by-word in the GUI instead of waiting
                     for the full response (eliminates the "frozen" feeling).
    * num_ctx      — calculated by safe_num_ctx_for_prompt() so the context
                     window is always large enough for the assembled prompt.
                     When the value equals get_model_num_ctx() the model was
                     already loaded at this size by prewarm_ollama() and Ollama
                     serves the query instantly from RAM.  When it is larger
                     (high chunk count), rag_query() re-prewarmed the model
                     first, so again no surprise reload mid-query.
    """
    import json as _json
    start_time    = time.time()
    QUERY_TIMEOUT = 300   # 5-minute hard cap

    num_ctx      = safe_num_ctx_for_prompt(prompt, max_tokens, OLLAMA_MODEL)
    prompt_words = len(prompt.split())
    prompt_toks  = int(prompt_words * 2.0)  # calibrated: actual ~1.94 t/w
    headroom     = num_ctx - prompt_toks - max_tokens

    if DEBUG_OUTPUT:
        print(f"\n🔬 DEBUG — query_ollama()")
        print(f"   Model    : {OLLAMA_MODEL}")
        print(f"   num_ctx  : {num_ctx}  (headroom ~{headroom} tokens)")
        print(f"   Prompt   : ~{prompt_words} words / ~{prompt_toks} tokens")
        print(f"   Response : up to {max_tokens} tokens")
        print(f"   Stream   : True")

    payload = {
        'model':      OLLAMA_MODEL,
        'prompt':     prompt,
        'stream':     True,
        'keep_alive': '30m',
        'options': {
            'num_predict': max_tokens,
            'num_ctx':     num_ctx,
            'temperature': 0.3,
            'num_gpu':     GPU_LAYERS,
        }
    }
    # Vision: attach base64 images if provided (requires a vision model like llava)
    if images_b64:
        payload['images'] = images_b64

    if DEBUG_OUTPUT:
        # ── Print exact DOS test command with full real payload ─────────────
        import json as _json_debug, os as _os_debug, tempfile as _tmp_debug
        _debug_payload = {
            'model':      OLLAMA_MODEL,
            'prompt':     prompt,
            'stream':     False,
            'keep_alive': '30m',
            'options': {
                'num_predict': max_tokens,
                'num_ctx':     num_ctx,
                'temperature': 0.3,
                'num_gpu':     GPU_LAYERS,
            }
        }
        _debug_file = _os_debug.path.join(_tmp_debug.gettempdir(), 'ai_prowler_query.json')
        with open(_debug_file, 'w', encoding='utf-8') as _f:
            _json_debug.dump(_debug_payload, _f, ensure_ascii=False, indent=2)
        print(f"\n{'='*60}")
        print(f"🖥️  EXACT DOS TEST COMMAND (full real prompt + options):")
        print(f"   Payload saved to: {_debug_file}")
        print(f"   Paste these 2 lines into a CMD window:")
        print(f"   ─────────────────────────────────────────────────────")
        print(f"   set OLLAMA_FILE={_debug_file}")
        print(f"   curl -s -X POST {OLLAMA_URL}/api/generate -H \"Content-Type: application/json\" --data-binary @%OLLAMA_FILE%")
        print(f"   ─────────────────────────────────────────────────────")
        print(f"   (stream:false so curl prints the complete answer at once)")
        print(f"{'='*60}\n")

    if GUI_MODE:
        # Stream tokens straight to ScrolledText via TextRedirector (sys.stdout)
        result = {'error': None, 'text': '', 'stopped': False}
        
        # Capture the current stdout (which should be TextRedirector)
        # BEFORE starting the thread, so the thread uses the correct stdout
        current_stdout = sys.stdout

        def _stream():
            try:
                t_conn = time.time()
                with requests.post(
                    f"{OLLAMA_URL}/api/generate",
                    json=payload, stream=True, timeout=QUERY_TIMEOUT
                ) as resp:
                    conn_ms   = int((time.time() - t_conn) * 1000)
                    first_tok = True
                    for raw in resp.iter_lines():
                        if not raw:
                            continue
                        try:
                            chunk = _json.loads(raw)
                        except Exception:
                            continue
                        tok = chunk.get('response', '')
                        # Stop button pressed — exit stream immediately
                        if QUERY_STOP:
                            result['stopped'] = True
                            break
                        if tok:
                            if first_tok:
                                ttft = int((time.time() - start_time) * 1000)
                                if DEBUG_OUTPUT:
                                    current_stdout.write(f"\n🔬 DEBUG — HTTP connected {conn_ms}ms  "
                                          f"first-token {ttft}ms\n")
                                    current_stdout.flush()
                                first_tok = False
                            result['text'] += tok
                            # Use the captured stdout explicitly
                            current_stdout.write(tok)
                            current_stdout.flush()
                        if chunk.get('done', False):
                            break
            except Exception as exc:
                result['error'] = exc

        t = threading.Thread(target=_stream, daemon=True)
        t.start()
        t.join(timeout=QUERY_TIMEOUT + 10)

        elapsed = time.time() - start_time
        m, s    = divmod(int(elapsed), 60)
        ts      = f"{m}m {s:02d}s" if m else f"{elapsed:.1f}s"

        if result['error']:
            exc = result['error']
            if DEBUG_OUTPUT:
                print(f"\n🔬 DEBUG — FAILED after {ts}: {exc}")
            if isinstance(exc, requests.exceptions.Timeout):
                return (f"\n\n❌ Timed out after {ts}.\n"
                        f"Try fewer Context Chunks in the GUI (current: high count).")
            if isinstance(exc, requests.exceptions.ConnectionError):
                return "\n\n❌ Cannot connect to Ollama. Is it running? (Try: ollama serve)"
            return f"\n\n❌ Error: {exc}"

        if DEBUG_OUTPUT:
            print(f"\n\n🔬 DEBUG — total query_ollama: {ts}")
        return result['text']

    else:
        # Terminal: spinner until first token, then print tokens live
        stop_spin = threading.Event()
        chars     = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']

        def _spin():
            i, t0 = 0, time.time()
            while not stop_spin.is_set():
                e = time.time() - t0
                m, s = divmod(int(e), 60)
                ts = f"{m}m {s:02d}s" if m else f"{s}s"
                print(f"\r   {chars[i%len(chars)]} Waiting… ({ts})",
                      end='', flush=True)
                i += 1
                time.sleep(0.1)

        spin = threading.Thread(target=_spin, daemon=True)
        spin.start()
        full = ''
        try:
            with requests.post(
                f"{OLLAMA_URL}/api/generate",
                json=payload, stream=True, timeout=QUERY_TIMEOUT
            ) as resp:
                first = True
                for raw in resp.iter_lines():
                    if not raw:
                        continue
                    try:
                        chunk = _json.loads(raw)
                    except Exception:
                        continue
                    tok = chunk.get('response', '')
                    if QUERY_STOP:
                        break
                    if tok:
                        if first:
                            stop_spin.set(); spin.join(timeout=0.5)
                            ttft = int((time.time() - start_time) * 1000)
                            print(f"\r   ✅ First token in {ttft}ms:\n")
                            first = False
                        full += tok
                        print(tok, end='', flush=True)
                    if chunk.get('done', False):
                        break
            stop_spin.set()
            elapsed = time.time() - start_time
            m, s = divmod(int(elapsed), 60)
            if DEBUG_OUTPUT:
                print(f"\n\n🔬 DEBUG — total: {f'{m}m {s:02d}s' if m else f'{elapsed:.1f}s'}")
            return full
        except requests.exceptions.Timeout:
            stop_spin.set()
            print(f"\r   ❌ Timeout after {int(time.time()-start_time)}s")
            return "Error: Timed out."
        except requests.exceptions.ConnectionError:
            stop_spin.set()
            print("\r   ❌ Connection failed")
            return "Error: Cannot connect to Ollama. (Try: ollama serve)"
        except Exception as e:
            stop_spin.set()
            print(f"\r   ❌ {e}")
            return f"Error: {e}"


def rag_query(question: str, n_contexts: int = None, verbose: bool = True, images_b64: list = None):
    """
    Perform RAG query: search + LLM

    Output is controlled by the SHOW_SOURCES global (saved in config):
      SHOW_SOURCES=False  — prints only the AI answer (default, clean GUI mode)
      SHOW_SOURCES=True   — prints full details: headers, chunk list, source
                            citations, timing (useful for CLI / debugging)

    Args:
        question: Question to ask
        n_contexts: Number of context chunks to retrieve (None = auto-calculate)
        verbose: Whether to print chunk previews (only used when SHOW_SOURCES=True)
    """
    total_start = time.time()

    # Auto-calculate optimal chunks if not specified
    if n_contexts is None:
        n_contexts = calculate_optimal_chunks(OLLAMA_MODEL)

    # ── Phase timing header ────────────────────────────────────────────────
    default_ctx = get_model_num_ctx(OLLAMA_MODEL)
    if DEBUG_OUTPUT:
        print(f"\n{'='*55}")
        print(f"⏱  RAG QUERY TIMING DEBUG")
        print(f"   Model       : {OLLAMA_MODEL}")
        print(f"   Chunks      : {n_contexts}  (~{n_contexts*750} tokens of context)")
        print(f"   Default ctx : {default_ctx} tokens")
        print(f"{'='*55}")

    if SHOW_SOURCES:
        print(f"\n{'='*60}")
        print(f"🔍 AI PROWLER QUERY")
        print(f"{'='*60}")
        print(f"❓ Question: {question}")
        print(f"🤖 Model: {OLLAMA_MODEL}")
        print(f"📚 Context chunks: {n_contexts}")
        print(f"{'='*60}\n")

    # Check Ollama
    if not check_ollama_available():
        print("⚠️  WARNING: Cannot connect to Ollama")
        print("   Make sure Ollama is running: ollama serve")
        print("   Or check if model is loaded: ollama list\n")

    # Phase 1: Vector search
    if SHOW_SOURCES:
        print(f"🔍 Searching for relevant context...")
    search_start = time.time()
    chunks = search_documents(question, n_results=n_contexts)
    search_time = time.time() - search_start
    if DEBUG_OUTPUT:
        print(f"⏱  [Phase 1] Vector search  : {search_time:.2f}s  ({len(chunks)} chunks found)")

    if not chunks:
        print("❌ No documents found. Index some documents first.")
        print("   Run: python rag_preprocessor.py index <directory>")
        return

    if SHOW_SOURCES:
        print(f"   ✅ Search complete! (took {search_time:.2f}s)\n")
        print(f"✅ Found {len(chunks)} relevant chunks:\n")
        for i, chunk in enumerate(chunks, 1):
            print(f"📄 [{i}] {chunk['metadata']['filename']}")
            print(f"    Path: {chunk['metadata']['filepath']}")
            print(f"    Chunk: {chunk['metadata']['chunk_index'] + 1}/"
                  f"{chunk['metadata']['total_chunks']}")
            print(f"    Similarity: {chunk['similarity']:.2%}")
            if verbose:
                preview = chunk['content'][:200].replace('\n', ' ')
                print(f"    Preview: {preview}...")
            print()

    # Phase 2: Build context
    ctx_start = time.time()
    context_parts = []
    for i, chunk in enumerate(chunks, 1):
        context_parts.append(
            f"[Source {i}: {chunk['metadata']['filename']}]\n{chunk['content']}"
        )
    context    = "\n\n---\n\n".join(context_parts)
    ctx_words  = len(context.split())
    ctx_tokens = int(ctx_words * 2.0)  # calibrated: actual ~1.94 t/w
    ctx_time   = time.time() - ctx_start
    if DEBUG_OUTPUT:
        print(f"⏱  [Phase 2] Build context  : {ctx_time:.2f}s  (~{ctx_words} words / ~{ctx_tokens} tokens)")

    # Build prompt
    if SHOW_SOURCES:
        prompt = f"""You are a helpful AI assistant with broad knowledge. Use the provided context as reference material when it is relevant to the question. For tasks like writing code, scripts, creative writing, analysis, or general knowledge questions, use your own expertise freely — you are not restricted to the context alone. When the context is relevant, cite which source number you are using.

Context:
{context}

Question: {question}

Answer (cite sources as [Source 1], [Source 2], etc. only when directly relevant):"""
    else:
        prompt = f"""You are a helpful AI assistant with broad knowledge. Use the provided context as reference material when it is relevant to the question. For tasks like writing code, scripts, creative writing, analysis, or general knowledge questions, use your own expertise freely — you are not restricted to the context alone. Be concise and clear.

Context:
{context}

Question: {question}

Answer:"""

    prompt_words  = len(prompt.split())
    prompt_tokens = int(prompt_words * 2.0)  # calibrated: actual ~1.94 t/w
    needed_ctx    = safe_num_ctx_for_prompt(prompt, 500, OLLAMA_MODEL)
    if DEBUG_OUTPUT:
        print(f"⏱  [Phase 3] Prompt size    : ~{prompt_words} words / ~{prompt_tokens} tokens")
        print(f"⏱  [Phase 3] num_ctx needed : {needed_ctx}  "
              f"(headroom ~{needed_ctx - prompt_tokens - 500} tokens)")

    # ── Query LLM directly (Ollama handles context size intelligently) ────
    # Since we prewarm at 8192 with keep_alive=0, Ollama keeps the model
    # loaded at that size. Any request with num_ctx ≤ 8192 is instant.
    # Ollama will automatically handle larger contexts if needed.
    
    # Phase 3: Query LLM — route to active provider
    llm_start = time.time()
    if SHOW_SOURCES:
        prov_name = EXTERNAL_PROVIDERS.get(ACTIVE_PROVIDER, {}).get('name', OLLAMA_MODEL)
        print(f"🤖 Querying {prov_name}…")
    else:
        if DEBUG_OUTPUT:
            prov_name = EXTERNAL_PROVIDERS.get(ACTIVE_PROVIDER, {}).get('name', OLLAMA_MODEL)
            print(f"⏱  [Phase 3] Querying {prov_name}…")

    if ACTIVE_PROVIDER == 'local':
        answer = query_ollama(prompt, images_b64=images_b64)
    else:
        status = get_provider_status(ACTIVE_PROVIDER)
        if status == 'timeout':
            until_str = get_provider_timeout_str(ACTIVE_PROVIDER)
            prov_name = EXTERNAL_PROVIDERS[ACTIVE_PROVIDER]['name']
            if FALLBACK_TO_LOCAL:
                print(f"⚠️ {prov_name} is rate-limited ({until_str}) — falling back to local Ollama.\n\n")
                answer = query_ollama(prompt, images_b64=images_b64)
            else:
                answer = (f"\n\n⚠️ {prov_name} is rate-limited {until_str}.\n"
                          f"Switch to a different provider or wait until the quota resets.")
        elif status == 'no_key':
            prov_name = EXTERNAL_PROVIDERS[ACTIVE_PROVIDER]['name']
            answer = (f"\n\n❌ No API key for {prov_name}.\n"
                      f"Add your key in Settings → External AI APIs.")
        else:
            answer = query_external_llm(ACTIVE_PROVIDER, prompt, images_b64=images_b64)
            # If external call returned an error/warning and fallback is on, use local
            if FALLBACK_TO_LOCAL and (answer.startswith('\n\n❌') or answer.startswith('\n\n⚠️')):
                prov_name = EXTERNAL_PROVIDERS[ACTIVE_PROVIDER]['name']
                # Print the actual error so user knows WHY it fell back
                print(f"⚠️ {prov_name} failed — falling back to local Ollama.\n"
                      f"Error detail: {answer.strip()}\n\n")
                answer = query_ollama(prompt, images_b64=images_b64)
            elif GUI_MODE:
                # External succeeded — print answer for GUI
                import sys as _sys
                _sys.stdout.write(answer)
                _sys.stdout.flush()
    llm_time   = time.time() - llm_start
    total_time = time.time() - total_start
    if DEBUG_OUTPUT:
        print(f"⏱  [Phase 3] LLM time       : {llm_time:.1f}s")
        print(f"⏱  [TOTAL]   End-to-end     : {total_time:.1f}s")
        print(f"{'='*55}")

    # Phase 4: Display result
    if SHOW_SOURCES:
        print()
        print(f"{'='*60}")
        print(f"💡 ANSWER")
        print(f"{'='*60}")
        print(answer)
        print(f"{'='*60}\n")

        print(f"📚 Sources cited:")
        for i, chunk in enumerate(chunks, 1):
            print(f"  [{i}] {chunk['metadata']['filename']}")
            print(f"      {chunk['metadata']['filepath']}")

        mins, secs = divmod(int(total_time), 60)
        time_str = f"{mins}m {secs:02d}s" if mins > 0 else f"{total_time:.1f}s"
        if DEBUG_OUTPUT:
            print(f"\n⏱️  Total query time: {time_str}")
        print()
    else:
        # Clean mode — answer was already streamed token-by-token above
        pass

# ═══════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════

def list_indexed_files():
    """List all indexed files with statistics"""
    client, embedding_func = get_chroma_client()
    
    try:
        collection = client.get_collection(
            name=COLLECTION_NAME,
            embedding_function=embedding_func
        )
    except:
        print("❌ No indexed documents found.")
        print("   Run: python rag_preprocessor.py index <directory>")
        return
    
    # Get all items
    results = collection.get()
    
    if len(results['ids']) == 0:
        print("📭 Database is empty. No documents indexed yet.")
        return
    
    # Extract unique files
    files = {}
    for metadata in results['metadatas']:
        filepath = metadata['filepath']
        if filepath not in files:
            files[filepath] = {
                'chunks': 0,
                'filename': metadata['filename'],
                'extension': metadata.get('extension', ''),
                'indexed_date': metadata.get('indexed_date', 'Unknown')
            }
        files[filepath]['chunks'] += 1
    
    # Display
    print(f"\n{'='*60}")
    print(f"📚 INDEXED DOCUMENTS")
    print(f"{'='*60}")
    print(f"Total files: {len(files)}")
    print(f"Total chunks: {len(results['ids'])}")
    print(f"{'='*60}\n")
    
    for filepath, info in sorted(files.items()):
        print(f"📄 {info['filename']}")
        print(f"   Path: {filepath}")
        print(f"   Type: {info['extension']}")
        print(f"   Chunks: {info['chunks']}")
        print(f"   Indexed: {info['indexed_date'][:10]}")
        print()

def show_stats():
    """Show database statistics"""
    client, embedding_func = get_chroma_client()
    
    try:
        collection = client.get_collection(
            name=COLLECTION_NAME,
            embedding_function=embedding_func
        )
    except:
        print("❌ No indexed documents found.")
        return
    
    total = collection.count()
    
    if total == 0:
        print("📭 Database is empty.")
        return
    
    # Get sample to analyze
    results = collection.get(limit=min(1000, total))
    
    # Count by extension
    extensions = {}
    for metadata in results['metadatas']:
        ext = metadata.get('extension', 'unknown')
        extensions[ext] = extensions.get(ext, 0) + 1
    
    # Count unique files
    unique_files = set(m['filepath'] for m in results['metadatas'])
    
    print(f"\n{'='*60}")
    print(f"📊 DATABASE STATISTICS")
    print(f"{'='*60}")
    print(f"Total chunks: {total:,}")
    print(f"Unique files: {len(unique_files):,}")
    print(f"Database path: {CHROMA_DB_PATH}")
    print(f"\nBy file type:")
    for ext, count in sorted(extensions.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / len(results['metadatas'])) * 100
        print(f"  {ext:10s} {count:5d} chunks ({percentage:5.1f}%)")
    print(f"{'='*60}\n")

def clear_database(confirm: bool = False):
    """Clear all indexed documents"""
    if not confirm:
        response = input("⚠️  This will delete ALL indexed documents. Continue? (yes/NO): ")
        if response.lower() != 'yes':
            print("Cancelled.")
            return
    
    client, _ = get_chroma_client()
    try:
        client.delete_collection(name=COLLECTION_NAME)
        print("✅ Database cleared successfully.")
    except:
        print("ℹ️  Database was already empty or doesn't exist.")

# ═══════════════════════════════════════════════════════════
# CLI INTERFACE
# ═══════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════
# FILE TRACKING AND CHANGE DETECTION
# ═══════════════════════════════════════════════════════════

TRACKING_DB  = Path.home() / '.rag_file_tracking.json'

# ── Per-email incremental index tracking ─────────────────────────────────────
# Stores a set of message-ID hashes for each indexed archive file so that on
# re-import only genuinely new messages are indexed and removed ones are cleaned
# from ChromaDB.  Covers .mbox, .eml (treated as single-message), and .emlx.
# (.msg files use a similar path via their PR_INTERNET_MESSAGE_ID property.)
EMAIL_INDEX_DB = Path.home() / '.rag_email_index.json'

def _make_message_uid(msg_id_header: str, fallback_parts: tuple) -> str:
    """
    Return a stable, compact identifier for one email message.

    Priority:
      1. Message-ID header (RFC 5322 globally unique)  →  md5(stripped value)
      2. Composite fallback  →  md5(from + date + subject)

    Using md5 (not for security — just for a fixed-length key safe to use as a
    ChromaDB metadata value and JSON key).
    """
    import hashlib
    raw = (msg_id_header or "").strip().strip("<>").strip()
    if not raw:
        raw = "|".join(str(p) for p in fallback_parts)
    return hashlib.md5(raw.encode("utf-8", errors="ignore")).hexdigest()

def load_email_index() -> dict:
    """Load the per-email incremental tracking DB.  Returns {} on missing/corrupt."""
    if EMAIL_INDEX_DB.exists():
        try:
            with open(EMAIL_INDEX_DB, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_email_index(db: dict) -> bool:
    """Persist the per-email incremental tracking DB."""
    try:
        with open(EMAIL_INDEX_DB, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2)
        return True
    except Exception as e:
        print(f"⚠️  Could not save email index: {e}")
        return False

# EMAIL_ARCHIVE_EXTENSIONS: multi-message archive types handled by the
# per-email incremental indexer (index_email_archive).  Adding a new format
# here requires a matching iter_*_emails() generator in index_email_archive().
#
# Provider → export format reference:
#   Gmail (Google Takeout)  → .mbox
#   Apple Mail              → .mbox (File→Export Mailbox) or .emlx (internal)
#   iCloud Mail             → .mbox (via Apple Mail export)
#   Thunderbird             → .mbox (per-folder file in profile)
#   Yahoo Mail              → .mbox (via MailStore/ImapSync) or folder of .eml
#   Outlook / Exchange      → .pst/.ost (needs conversion) or folder of .eml
#   Windows Live Mail       → folder of .eml files
#   GNU Emacs RMAIL         → .rmail / .babyl
#   Legacy Unix MMDF        → .mmdf
EMAIL_ARCHIVE_EXTENSIONS = {'.mbox', '.rmail', '.babyl', '.mmdf'}

def load_tracking_database():
    """Load file tracking database"""
    if TRACKING_DB.exists():
        try:
            with open(TRACKING_DB, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_tracking_database(db):
    """Save file tracking database"""
    try:
        with open(TRACKING_DB, 'w') as f:
            json.dump(db, f, indent=2)
        return True
    except Exception as e:
        print(f"⚠️  Warning: Could not save tracking database: {e}")
        return False

def get_file_modification_info(filepath):
    """Get file modification time"""
    try:
        stat = os.stat(filepath)
        return {
            'modified': stat.st_mtime,
            'modified_human': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'size': stat.st_size
        }
    except:
        return None

def scan_directory_for_changes(directory, recursive=True, quiet=False):
    """Scan directory and detect new/modified files"""
    
    root_path = Path(directory).resolve()
    
    if not root_path.exists():
        print(f"❌ Error: Directory not found: {directory}")
        return None
    
    # Load tracking database
    tracking_db = load_tracking_database()
    dir_key = normalise_path(str(root_path))
    
    if dir_key not in tracking_db:
        tracking_db[dir_key] = {
            'first_scan': datetime.now().isoformat(),
            'last_scan': None,
            'files': {}
        }
    
    # Results
    results = {
        'new_files': [],
        'modified_files': [],
        'unchanged_files': [],
        'deleted_files': [],
        'all_files': [],
        'total_size': 0,
        'scan_time': datetime.now().isoformat()
    }
    
    if not quiet:
        print(f"🔍 Scanning: {root_path}")
    if not quiet:
        if tracking_db[dir_key]['last_scan']:
            last_scan = datetime.fromisoformat(tracking_db[dir_key]['last_scan'])
            print(f"   Last scanned: {last_scan.strftime('%Y-%m-%d %H:%M:%S')}")
        else:
            print(f"   First scan of this directory")
        print()
    
    # Current scan
    current_files = {}
    file_count = 0
    
    # Walk directory
    for dirpath, dirnames, filenames in os.walk(root_path):
        
        # Skip directories
        dirnames_copy = dirnames.copy()
        for dirname in dirnames_copy:
            if dirname in ['node_modules', '.git', '.svn', '__pycache__', 'venv', 
                          '.venv', 'build', 'dist', '.idea', '.vscode', 'rag_database'] or dirname.startswith('.'):
                dirnames.remove(dirname)
        
        # Stop if not recursive
        if not recursive and dirpath != str(root_path):
            break
        
        # Process files
        for filename in filenames:
            filepath = normalise_path(os.path.join(dirpath, filename))
            ext = Path(filename).suffix.lower()

            if ext in SUPPORTED_EXTENSIONS:
                file_info = get_file_modification_info(filepath)
                
                if file_info:
                    file_count += 1
                    file_info['path'] = filepath
                    file_info['name'] = filename
                    
                    current_files[filepath] = file_info
                    results['all_files'].append(file_info)
                    results['total_size'] += file_info['size']
                    
                    # Check if new or modified
                    if filepath not in tracking_db[dir_key]['files']:
                        # New file
                        results['new_files'].append(file_info)
                        file_info['status'] = 'NEW'
                    else:
                        old_modified = tracking_db[dir_key]['files'][filepath]['modified']
                        if file_info['modified'] > old_modified:
                            # Modified file
                            results['modified_files'].append(file_info)
                            file_info['status'] = 'MODIFIED'
                        else:
                            # Unchanged
                            results['unchanged_files'].append(file_info)
                            file_info['status'] = 'UNCHANGED'
    
    # Check for deleted files
    for filepath in list(tracking_db[dir_key]['files'].keys()):
        filepath = normalise_path(filepath)
        if filepath not in current_files:
            old_file = tracking_db[dir_key]['files'][filepath].copy()
            old_file['path'] = filepath
            old_file['status'] = 'DELETED'
            results['deleted_files'].append(old_file)
    
    return results, tracking_db, dir_key

def print_scan_report(results, show_details=True):
    """Print scan report"""
    
    print("=" * 70)
    print("📊 FILE SCAN REPORT")
    print("=" * 70)
    print()
    
    # Summary
    total = len(results['all_files'])
    new = len(results['new_files'])
    modified = len(results['modified_files'])
    unchanged = len(results['unchanged_files'])
    deleted = len(results['deleted_files'])
    
    print("SUMMARY:")
    print(f"  📁 Total files: {total}")
    print(f"  🆕 New: {new}")
    print(f"  📝 Modified: {modified}")
    print(f"  ✅ Unchanged: {unchanged}")
    print(f"  🗑️  Deleted: {deleted}")
    print()
    
    changes = new + modified
    if changes == 0:
        print("✨ No changes detected - your index is up to date!")
    else:
        print(f"⚠️  {changes} file(s) need to be re-indexed")
    
    print()
    
    # Show details if requested
    if show_details and (results['new_files'] or results['modified_files']):
        
        if results['new_files']:
            print("=" * 70)
            print(f"🆕 NEW FILES ({len(results['new_files'])})")
            print("=" * 70)
            for file_info in results['new_files'][:10]:
                print(f"  {file_info['modified_human']}  {Path(file_info['path']).name}")
            if len(results['new_files']) > 10:
                print(f"  ... and {len(results['new_files']) - 10} more")
            print()
        
        if results['modified_files']:
            print("=" * 70)
            print(f"📝 MODIFIED FILES ({len(results['modified_files'])})")
            print("=" * 70)
            for file_info in results['modified_files'][:10]:
                print(f"  {file_info['modified_human']}  {Path(file_info['path']).name}")
            if len(results['modified_files']) > 10:
                print(f"  ... and {len(results['modified_files']) - 10} more")
            print()
        
        if results['deleted_files']:
            print("=" * 70)
            print(f"🗑️  DELETED FILES ({len(results['deleted_files'])})")
            print("=" * 70)
            for file_info in results['deleted_files'][:10]:
                print(f"  {Path(file_info['path']).name}")
            if len(results['deleted_files']) > 10:
                print(f"  ... and {len(results['deleted_files']) - 10} more")
            print()

def command_scan(directory, recursive=True):
    """Scan directory and show file changes"""
    
    result = scan_directory_for_changes(directory, recursive)
    
    if result is None:
        return
    
    results, tracking_db, dir_key = result
    
    # Print report
    print_scan_report(results)
    
    # Save tracking database
    if save_tracking_database(tracking_db):
        print(f"✅ Tracking database updated: {TRACKING_DB}")
    else:
        print(f"⚠️  Could not update tracking database")
    
    print()
    
    # Next steps
    changes = len(results['new_files']) + len(results['modified_files'])
    if changes > 0:
        print("=" * 70)
        print("NEXT STEPS")
        print("=" * 70)
        print()
        print(f"You have {changes} changed file(s)")
        print()
        print("To update your index:")
        print(f"  rag update {directory}")
        print()

def command_check(directory, recursive=True):
    """Quick check for changes without updating database"""
    
    result = scan_directory_for_changes(directory, recursive)
    
    if result is None:
        return
    
    results, _, _ = result
    
    # Print brief report
    print_scan_report(results, show_details=False)
    
    changes = len(results['new_files']) + len(results['modified_files'])
    if changes > 0:
        print()
        print(f"To see details: rag scan {directory}")
        print(f"To update index: rag update {directory}")
        print()

def command_update(directory, recursive=True, auto_confirm=False):
    """Check for changes and update index with new/modified files"""
    
    print("=" * 70)
    print("🔍 CHECKING FOR CHANGES")
    print("=" * 70)
    print()
    
    result = scan_directory_for_changes(directory, recursive)
    
    if result is None:
        return
    
    results, tracking_db, dir_key = result
    
    # Print report
    print_scan_report(results)
    
    changes = len(results['new_files']) + len(results['modified_files'])
    
    if changes == 0:
        print("✅ No changes detected - index is up to date!")
        print()
        # Still update tracking database
        if save_tracking_database(tracking_db):
            print("✅ Tracking database updated")
        return
    
    # Ask for confirmation unless auto-confirmed
    if not auto_confirm:
        print()
        print("=" * 70)
        response = input(f"Update index with {changes} changed file(s)? (y/n): ")
        if response.lower() != 'y':
            print("\nUpdate cancelled.")
            return
    
    print()
    print("=" * 70)
    print(f"🚀 UPDATING INDEX ({changes} files)")
    print("=" * 70)
    print()
    
    # Initialize database once for all updates
    client, embedding_func = get_chroma_client()
    collection = create_or_get_collection(client, embedding_func)
    
    # Index only the specific changed/new files — not entire directories
    changed_files = results['new_files'] + results['modified_files']
    updated = 0
    failed = 0
    
    for i, file_info in enumerate(changed_files, 1):
        filepath = normalise_path(file_info['path'])
        filename = file_info['name']
        ext      = Path(filepath).suffix.lower()
        status   = file_info.get('status', '')
        
        print(f"[{i}/{changes}] [{status}] {filename}")

        # ── Email archive — incremental per-message update ─────────────────────
        if ext in EMAIL_ARCHIVE_EXTENSIONS:
            arc_stats = index_email_archive(filepath)
            if arc_stats["processed"] > 0 or arc_stats.get("removed", 0) > 0:
                print(f"  ✅ {arc_stats['processed']} new message(s) indexed, "
                      f"{arc_stats.get('removed', 0)} removed, "
                      f"{arc_stats['skipped']} unchanged")
                updated += 1
            else:
                print(f"  ℹ️  No email changes (all messages already indexed)")
            print()
            continue

        # ── Normal file ────────────────────────────────────────────────────────
        file_data = load_file(filepath)
        if not file_data:
            print(f"  ⚠️  Could not load file — skipping")
            failed += 1
            continue
        
        chunks = chunk_text(file_data['content'], CHUNK_SIZE, CHUNK_OVERLAP)
        if not chunks:
            print(f"  ⚠️  Empty file — skipping")
            failed += 1
            continue
        
        ids = [f"{filepath}__chunk_{j}" for j in range(len(chunks))]
        metadatas = [{
            'filepath': filepath,
            'filename': file_data['filename'],
            'chunk_index': j,
            'total_chunks': len(chunks),
            'extension': file_data['extension'],
            'indexed_date': datetime.now().isoformat()
        } for j in range(len(chunks))]
        
        try:
            # Remove stale chunks for this file before re-adding
            collection.delete(where={"filepath": filepath})
            collection.add(ids=ids, documents=chunks, metadatas=metadatas)
            print(f"  ✅ Indexed {len(chunks)} chunk(s)")
            updated += 1
        except Exception as e:
            print(f"  ❌ Error: {e}")
            failed += 1
        print()
    
    print(f"{'='*70}")
    print(f"✨ UPDATE COMPLETE: {updated} file(s) indexed, {failed} skipped")
    print(f"{'='*70}")
    print()
    
    # Update tracking database
    tracking_db[dir_key]['files'] = {}
    for file_info in results['all_files']:
        if file_info.get('status') != 'DELETED':
            tracking_db[dir_key]['files'][normalise_path(file_info['path'])] = {
                'modified': file_info['modified'],
                'modified_human': file_info['modified_human'],
                'size': file_info['size']
            }
    
    tracking_db[dir_key]['last_scan'] = results['scan_time']
    
    if save_tracking_database(tracking_db):
        print("✅ Tracking database updated")
    
    # Regenerate auto-update script with latest directory list
    generate_auto_update_script()
    
    print()
    print("✅ Index update complete!")
    print()

# ═══════════════════════════════════════════════════════════
# AUTO-UPDATE LIST MANAGEMENT
# ═══════════════════════════════════════════════════════════

AUTO_UPDATE_LIST = Path.home() / '.rag_auto_update_dirs.json'

def load_auto_update_list():
    """Load list of directories to auto-update"""
    if AUTO_UPDATE_LIST.exists():
        try:
            with open(AUTO_UPDATE_LIST, 'r') as f:
                data = json.load(f)
                return data.get('directories', [])
        except:
            return []
    return []

def save_auto_update_list(directories):
    """Save list of directories to auto-update"""
    try:
        data = {
            'directories': directories,
            'last_updated': datetime.now().isoformat()
        }
        with open(AUTO_UPDATE_LIST, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"⚠️  Warning: Could not save auto-update list: {e}")
        return False

def add_to_auto_update_list(directory):
    """Add directory to auto-update list and regenerate script"""
    directory = str(Path(directory).resolve())
    dirs = load_auto_update_list()
    
    if directory not in dirs:
        dirs.append(directory)
        save_auto_update_list(dirs)
        
        # Auto-regenerate script with updated list
        generate_auto_update_script()
        
        return True  # New directory added
    
    return False  # Directory already in list

def remove_from_auto_update_list(directory):
    """Remove directory from auto-update list"""
    directory = normalise_path(str(Path(directory).resolve()))
    dirs = [normalise_path(d) for d in load_auto_update_list()]

    if directory in dirs:
        dirs.remove(directory)
        save_auto_update_list(dirs)


def remove_directory_from_index(directory: str) -> dict:
    """
    Fully untrack a directory — removes it from:
      1. The auto-update list  (~/.rag_auto_update_dirs.json)
      2. The file-tracking DB  (~/.rag_file_tracking.json)
      3. ChromaDB — deletes ALL chunks whose filepath starts with this directory

    Returns a dict with keys: chunks_removed, files_removed, errors
    """
    directory = normalise_path(str(Path(directory).resolve()))
    chunks_removed = 0
    files_removed  = 0
    errors         = []

    # 1. Remove from auto-update list
    try:
        dirs = [normalise_path(d) for d in load_auto_update_list()]
        if directory in dirs:
            dirs.remove(directory)
            save_auto_update_list(dirs)
    except Exception as e:
        errors.append(f"Auto-update list: {e}")

    # 2. Remove from file-tracking DB
    try:
        tracking_db = load_tracking_database()
        keys_to_remove = [k for k in tracking_db
                          if normalise_path(k) == directory
                          or normalise_path(k).startswith(directory + '/')]
        for k in keys_to_remove:
            del tracking_db[k]
        if keys_to_remove:
            save_tracking_database(tracking_db)
    except Exception as e:
        errors.append(f"Tracking DB: {e}")

    # 3. Remove all ChromaDB chunks for this directory
    # ChromaDB where-clause only supports exact match, not startswith.
    # We must fetch all matching IDs then delete by ID.
    try:
        client, embedding_func = get_chroma_client()
        try:
            collection = client.get_collection(
                name=COLLECTION_NAME,
                embedding_function=embedding_func
            )
        except Exception:
            collection = None   # collection doesn't exist yet — nothing to delete

        if collection:
            # Fetch in pages to handle large collections safely
            offset   = 0
            pagesize = 500
            ids_to_delete = []

            while True:
                batch = collection.get(
                    limit=pagesize,
                    offset=offset,
                    include=['metadatas']
                )
                if not batch['ids']:
                    break
                for doc_id, meta in zip(batch['ids'], batch['metadatas']):
                    fp = normalise_path(meta.get('filepath', ''))
                    if fp == directory or fp.startswith(directory + '/'):
                        ids_to_delete.append(doc_id)
                offset += pagesize
                if len(batch['ids']) < pagesize:
                    break

            if ids_to_delete:
                # Delete in batches of 100 (ChromaDB limit per call)
                for i in range(0, len(ids_to_delete), 100):
                    collection.delete(ids=ids_to_delete[i:i+100])
                chunks_removed = len(ids_to_delete)

            # Count distinct files removed
            files_removed = len({
                normalise_path(meta.get('filepath', ''))
                for meta in []   # already deleted — use ids count as proxy
            }) or (chunks_removed > 0 and 1)   # at least 1 file if chunks removed

    except Exception as e:
        errors.append(f"ChromaDB: {e}")

    # 4. Remove any email index entries for files inside this directory
    try:
        email_db = load_email_index()
        keys_to_remove = [k for k in email_db
                          if k == directory
                          or k.startswith(directory + '/')]
        for k in keys_to_remove:
            del email_db[k]
        if keys_to_remove:
            save_email_index(email_db)
    except Exception as e:
        errors.append(f"Email index: {e}")

    return {
        'chunks_removed': chunks_removed,
        'errors':         errors,
    }

def generate_auto_update_script():
    """Generate auto-update script for all tracked directories"""
    dirs = load_auto_update_list()
    
    if not dirs:
        print("⚠️  No directories in auto-update list")
        return None
    
    # Determine platform
    is_windows = sys.platform == 'win32'
    
    if is_windows:
        script_path = Path.home() / 'rag_auto_update.bat'
        script_content = generate_windows_script(dirs)
    else:
        script_path = Path.home() / 'rag_auto_update.sh'
        script_content = generate_unix_script(dirs)
    
    try:
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        # Make executable on Unix
        if not is_windows:
            os.chmod(script_path, 0o755)
        
        return script_path
    except Exception as e:
        print(f"❌ Error creating script: {e}")
        return None

def generate_windows_script(directories):
    """Generate Windows batch script"""
    script = """@echo off
REM ============================================================
REM AI Prowler Auto-Update Script
REM Auto-generated from indexed directories
REM Last updated: {timestamp}
REM ============================================================

echo ============================================================
echo AI PROWLER AUTO-UPDATE
echo ============================================================
echo Started: %DATE% %TIME%
echo.

""".format(timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    for i, directory in enumerate(directories, 1):
        dir_name = Path(directory).name or Path(directory).as_posix()
        script += f"""echo [{i}/{len(directories)}] Updating: {dir_name}
python rag_preprocessor.py update "{directory}" --yes
if errorlevel 1 (
    echo   ❌ Update failed
) else (
    echo   ✅ Updated
)
echo.

"""
    
    script += """echo ============================================================
echo COMPLETE
echo ============================================================
echo Finished: %DATE% %TIME%
echo.

REM Optional: Log completion
echo [%DATE% %TIME%] Auto-update completed >> "%USERPROFILE%\\.rag_update.log"
"""
    
    return script

def generate_unix_script(directories):
    """Generate Unix shell script"""
    script = """#!/bin/bash
# ============================================================
# AI Prowler Auto-Update Script
# Auto-generated from indexed directories
# Last updated: {timestamp}
# ============================================================

echo "============================================================"
echo "AI PROWLER AUTO-UPDATE"
echo "============================================================"
echo "Started: $(date)"
echo

""".format(timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    for i, directory in enumerate(directories, 1):
        dir_name = Path(directory).name or Path(directory).as_posix()
        script += f"""echo "[{i}/{len(directories)}] Updating: {dir_name}"
if python3 rag_preprocessor.py update "{directory}" --yes; then
    echo "  ✅ Updated"
else
    echo "  ❌ Update failed"
fi
echo

"""
    
    script += """echo "============================================================"
echo "COMPLETE"
echo "============================================================"
echo "Finished: $(date)"

# Optional: Log completion
echo "[$(date)] Auto-update completed" >> ~/.rag_update.log
"""
    
    return script

def command_auto_update():
    """Run auto-update on all tracked directories"""
    dirs = load_auto_update_list()
    
    if not dirs:
        print("⚠️  No directories in auto-update list")
        print("   Index some directories first: rag index <directory>")
        return
    
    print("=" * 70)
    print("🚀 AUTO-UPDATE ALL TRACKED DIRECTORIES")
    print("=" * 70)
    print()
    print(f"Found {len(dirs)} directory(ies) to update:")
    for directory in dirs:
        print(f"  • {directory}")
    print()
    
    response = input("Update all directories? (y/n): ")
    if response.lower() != 'y':
        print("Cancelled.")
        return
    
    print()
    
    # Update each directory
    for i, directory in enumerate(dirs, 1):
        dir_name = Path(directory).name or Path(directory).as_posix()
        print(f"[{i}/{len(dirs)}] {dir_name}")
        print()
        
        try:
            command_update(directory, recursive=True, auto_confirm=True)
        except Exception as e:
            print(f"  ❌ Error: {e}")
        
        print()
    
    print("=" * 70)
    print("✅ AUTO-UPDATE COMPLETE")
    print("=" * 70)

def command_list_auto_update():
    """List directories in auto-update list"""
    dirs = load_auto_update_list()
    
    print()
    print("=" * 70)
    print("📋 AUTO-UPDATE DIRECTORY LIST")
    print("=" * 70)
    print()
    
    if not dirs:
        print("No directories in auto-update list.")
        print()
        print("Directories are added automatically when you run:")
        print("  rag index <directory>")
        print()
    else:
        print(f"Found {len(dirs)} directory(ies):")
        print()
        for i, directory in enumerate(dirs, 1):
            print(f"  {i}. {directory}")
        print()
        print("These directories will be updated when you run:")
        print("  rag auto-update")
        print()
        print("Or generate a script:")
        print("  rag generate-script")
        print()

def command_generate_script():
    """Generate auto-update script"""
    dirs = load_auto_update_list()
    
    if not dirs:
        print("⚠️  No directories in auto-update list")
        print("   Index some directories first: rag index <directory>")
        return
    
    print()
    print("=" * 70)
    print("📝 GENERATING AUTO-UPDATE SCRIPT")
    print("=" * 70)
    print()
    print(f"Including {len(dirs)} directory(ies):")
    for directory in dirs:
        print(f"  • {directory}")
    print()
    
    script_path = generate_auto_update_script()
    
    if script_path:
        print(f"✅ Script created: {script_path}")
        print()
        print("To use:")
        if sys.platform == 'win32':
            print(f"  1. Double-click: {script_path}")
            print(f"  2. Or schedule in Task Scheduler")
        else:
            print(f"  1. Run: {script_path}")
            print(f"  2. Or schedule in cron/launchd")
        print()

def command_config(args):
    """Configure RAG settings"""
    global OLLAMA_MODEL
    
    if args.show:
        # Show current configuration
        print()
        print("=" * 70)
        print("⚙️  CURRENT CONFIGURATION")
        print("=" * 70)
        print()
        print(f"Model: {OLLAMA_MODEL}")
        print(f"Ollama URL: {OLLAMA_URL}")
        print(f"Chunk size: {CHUNK_SIZE} words")
        print(f"Chunk overlap: {CHUNK_OVERLAP} words")
        print(f"Context window: {get_model_context_window(OLLAMA_MODEL):,} tokens")
        print(f"Optimal chunks: {calculate_optimal_chunks(OLLAMA_MODEL)}")
        print()
        print(f"Config file: {CONFIG_FILE}")
        print()
        return
    
    if args.list_models:
        # List available models
        print()
        print("=" * 70)
        print("📋 AVAILABLE MODELS")
        print("=" * 70)
        print()
        print("Llama 3.2 (Recommended):")
        print("  • llama3.2:1b   - 128K context, fastest")
        print("  • llama3.2:3b   - 128K context, balanced")
        print()
        print("Llama 3.1:")
        print("  • llama3.1:8b   - 128K context, high quality")
        print("  • llama3.1:70b  - 128K context, best quality (slow)")
        print()
        print("Qwen 2.5:")
        print("  • qwen2.5:0.5b  - 32K context, ultra-fast")
        print("  • qwen2.5:7b    - 128K context, excellent")
        print("  • qwen2.5:14b   - 128K context, very good")
        print()
        print("Mistral:")
        print("  • mistral:7b    - 32K context, good quality")
        print("  • mixtral:8x7b  - 32K context, excellent")
        print()
        print("To install a model:")
        print("  ollama pull <model-name>")
        print()
        print("To set as default:")
        print("  rag config --model <model-name>")
        print()
        return
    
    if args.model:
        # Set model
        print()
        print("=" * 70)
        print("⚙️  UPDATING CONFIGURATION")
        print("=" * 70)
        print()
        
        # Check if model is available
        print(f"Checking if {args.model} is available...")
        try:
            response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
            models = response.json().get('models', [])
            model_names = [m['name'] for m in models]
            
            if args.model not in model_names:
                print()
                print(f"⚠️  Model '{args.model}' not found locally")
                print()
                print("Install it first:")
                print(f"  ollama pull {args.model}")
                print()
                return
        except:
            print("⚠️  Could not connect to Ollama to verify model")
            print("   Saving configuration anyway...")
        
        # Save configuration
        if save_config(model=args.model):
            OLLAMA_MODEL = args.model
            
            print()
            print(f"✅ Model set to: {args.model}")
            print(f"   Context window: {get_model_context_window(args.model):,} tokens")
            print(f"   Optimal chunks: {calculate_optimal_chunks(args.model)}")
            print()
            print("Configuration saved!")
            print()
        else:
            print()
            print("❌ Could not save configuration")
            print()

def command_license():
    """Manage license key"""
    
    current_license = load_license_key()
    
    print()
    print("=" * 70)
    print("🔑 LICENSE MANAGEMENT")
    print("=" * 70)
    print()
    
    if current_license and validate_license_key(current_license):
        print(f"Current license: {current_license}")
        print("Status: ✅ Valid")
        print()
        print(f"Machine ID: {generate_machine_id()}")
        print()
        
        response = input("Enter new license key? (y/n): ")
        if response.lower() != 'y':
            return
        print()
    
    # Prompt for new license
    if not prompt_for_license():
        sys.exit(1)

# ═══════════════════════════════════════════════════════════
# MAIN FUNCTION
# ═══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="AI Prowler Document Preprocessor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Index documents (automatically sets up tracking)
  python rag_preprocessor.py index ~/Documents
  python rag_preprocessor.py index /path/to/unity/project --no-recursive
  
  # Ask questions
  python rag_preprocessor.py query "What is NEAT mutation rate?"
  python rag_preprocessor.py query "How does elite preservation work?" -n 5
  
  # Manage database
  python rag_preprocessor.py list
  python rag_preprocessor.py stats
  python rag_preprocessor.py clear
  
  # Keep index up-to-date (check + update in one command)
  python rag_preprocessor.py update ~/Documents
  python rag_preprocessor.py update ~/Documents --yes  # Skip confirmation
  
  # Auto-update all tracked directories
  python rag_preprocessor.py auto-update             # Update all at once
  python rag_preprocessor.py list-dirs               # Show tracked directories
  python rag_preprocessor.py generate-script         # Create update script
  
  # Manual tracking (optional - index does this automatically)
  python rag_preprocessor.py scan ~/Documents
  python rag_preprocessor.py check ~/Documents
  
  # Check setup
  python rag_preprocessor.py test
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Index command
    index_parser = subparsers.add_parser('index', help='Index documents from directory')
    index_parser.add_argument('directory', help='Directory containing documents')
    index_parser.add_argument('--no-recursive', action='store_true',
                             help='Do not search subdirectories')
    
    # Query command
    query_parser = subparsers.add_parser('query', help='Ask a question about indexed documents')
    query_parser.add_argument('question', help='Question to ask')
    query_parser.add_argument('-n', '--num-contexts', type=int, default=3,
                            help='Number of context chunks to use (default: 3)')
    query_parser.add_argument('--quiet', action='store_true',
                            help='Less verbose output')
    
    # List command
    subparsers.add_parser('list', help='List all indexed files')
    
    # Stats command
    subparsers.add_parser('stats', help='Show database statistics')
    
    # Clear command
    clear_parser = subparsers.add_parser('clear', help='Clear all indexed documents')
    clear_parser.add_argument('--force', action='store_true',
                            help='Skip confirmation prompt')
    
    # Test command
    subparsers.add_parser('test', help='Test connection to Ollama')
    
    # Auto-update commands
    subparsers.add_parser('auto-update', help='Update all tracked directories')
    subparsers.add_parser('list-dirs', help='List directories in auto-update list')
    subparsers.add_parser('generate-script', help='Generate auto-update script')
    
    # Configuration commands
    config_parser = subparsers.add_parser('config', help='Configure RAG settings')
    config_parser.add_argument('--model', help='Set Ollama model')
    config_parser.add_argument('--list-models', action='store_true', help='List available models')
    config_parser.add_argument('--show', action='store_true', help='Show current configuration')
    
    # License command
    subparsers.add_parser('license', help='Enter or check license key')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan directory for new/modified files')
    scan_parser.add_argument('directory', help='Directory to scan')
    scan_parser.add_argument('--no-recursive', action='store_true',
                            help='Do not search subdirectories')
    
    # Check command
    check_parser = subparsers.add_parser('check', help='Quick check for changes')
    check_parser.add_argument('directory', help='Directory to check')
    check_parser.add_argument('--no-recursive', action='store_true',
                             help='Do not search subdirectories')
    
    # Update command
    update_parser = subparsers.add_parser('update', help='Check for changes and update index')
    update_parser.add_argument('directory', help='Directory to update')
    update_parser.add_argument('--no-recursive', action='store_true',
                               help='Do not search subdirectories')
    update_parser.add_argument('--yes', '-y', action='store_true',
                               help='Skip confirmation prompt')
    
    args = parser.parse_args()
    
    # Execute command
    if args.command == 'index':
        recursive = not args.no_recursive
        index_directory(args.directory, recursive=recursive)
        
    elif args.command == 'query':
        rag_query(args.question, n_contexts=args.num_contexts, 
                 verbose=not args.quiet)
        
    elif args.command == 'list':
        list_indexed_files()
        
    elif args.command == 'stats':
        show_stats()
        
    elif args.command == 'clear':
        clear_database(confirm=args.force)
        
    elif args.command == 'test':
        print("\n🔧 Testing Ollama connection...")
        if check_ollama_available():
            print("✅ Ollama is running and accessible")
            print(f"   URL: {OLLAMA_URL}")
            print(f"   Model: {OLLAMA_MODEL}")
        else:
            print("❌ Cannot connect to Ollama")
            print("   Please start Ollama: ollama serve")
            print(f"   Or check URL: {OLLAMA_URL}")
    
    elif args.command == 'scan':
        recursive = not args.no_recursive
        command_scan(args.directory, recursive=recursive)
    
    elif args.command == 'check':
        recursive = not args.no_recursive
        command_check(args.directory, recursive=recursive)
    
    elif args.command == 'update':
        recursive = not args.no_recursive
        auto_confirm = args.yes if hasattr(args, 'yes') else False
        command_update(args.directory, recursive=recursive, auto_confirm=auto_confirm)
    
    elif args.command == 'auto-update':
        command_auto_update()
    
    elif args.command == 'list-dirs':
        command_list_auto_update()
    
    elif args.command == 'generate-script':
        command_generate_script()
    
    elif args.command == 'config':
        command_config(args)
    
    elif args.command == 'license':
        command_license()
        
    else:
        parser.print_help()

if __name__ == "__main__":
    # Check license before running (if required)
    if LICENSE_REQUIRED and not check_license():
        if not prompt_for_license():
            print("License required. Exiting.")
            sys.exit(1)
    
    main()
