import os
import logging
import requests
import re
from celery import Celery
from ipaddress import ip_address, ip_network
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor
from features_config import FEATURE_FLAGS

# Initialize Celery
celery = Celery("tasks")
celery.config_from_object("celeryconfig")

# Cloudflare creds
API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
ACC_ID = os.getenv("CLOUDFLARE_ACCOUNT_ID")

# Excluded CIDRs
excluded_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

# — Setup logging —
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# — Option 1: Reuse HTTP connections with built-in retries —
session = requests.Session()
retry_strategy = Retry(
    total=5, backoff_factor=1, status_forcelist=[502, 503, 504], allowed_methods=["GET"]
)
adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10)
session.mount("https://", adapter)


def is_feature_enabled(feature_name):
    return FEATURE_FLAGS.get(feature_name, False)


def is_ip_in_cidr(ip, cidr):
    return ip_address(ip) in ip_network(cidr)


def is_ip_excluded(ip_or_cidr):
    try:
        net = ip_network(ip_or_cidr, strict=False)
    except ValueError:
        return False
    for exc in excluded_cidrs:
        exc_net = ip_network(exc)
        if net.subnet_of(exc_net) and net.prefixlen <= exc_net.prefixlen:
            return True
    return False


def safe_get_json(response):
    try:
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error {response.status_code}: {e}")
        raise
    except ValueError as e:
        logger.error(f"JSON decode error: {e}")
        return {}


def scan_cloudflare_lists(ip, api_token, account_id):
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    base_url = (
        f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway/lists"
    )
    resp = session.get(base_url, headers=headers)
    lists = safe_get_json(resp).get("result", [])
    results = []

    with ThreadPoolExecutor(max_workers=8) as executor:
        future_to_list = {}
        for lst in lists:
            if lst.get("type", "").upper() != "IP":
                continue
            url = f"{base_url}/{lst['id']}/items"
            future = executor.submit(session.get, url, headers=headers)
            future_to_list[future] = {"name": lst["name"], "id": lst["id"]}

        for future, list_info in future_to_list.items():
            list_name = list_info["name"]
            list_id = list_info["id"]
            try:
                entries = safe_get_json(future.result()).get("result", [])
            except Exception as e:
                logger.error(f"Failed to fetch items for {list_name} ({list_id}): {e}")
                continue

            for entry in entries:
                cidr = entry["value"]
                description = entry.get("description", "")
                if is_ip_in_cidr(ip, cidr) and not is_ip_excluded(cidr):
                    results.append(
                        {
                            "ip": ip,
                            "list_id": list_id,
                            "list_name": list_name,
                            "description": description or None,
                        }
                    )
    return results


def scan_cloudflare_policies(ip, api_token, account_id, zt_list_id=[], port=None,):
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway/rules"
    resp = session.get(url, headers=headers)
    policies = safe_get_json(resp).get("result", [])
    results = []
    results_list = []
    if is_feature_enabled("port"):
        results_port = []

    for p in policies:
        name, traffic = p["name"], p.get("traffic", "")
        if re.search(rf"\b{re.escape(ip)}\b", traffic):
            # results.append(f"IPv4 {ip} found in policy: {name}")
            results.append(
                {
                    "ip": ip,
                    "policy_name": name,
                }
            )
        else:
            for cidr in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", traffic):
                if is_ip_in_cidr(ip, cidr) and not is_ip_excluded(cidr):
                    # results.append(f"IP {ip} found in policy: {name}")
                    results.append(
                        {
                            "ip": ip,
                            "policy_name": name,
                        }
                    )
                    break

        # Check for list ID usage
        for list_item in zt_list_id:
            list_id, list_name = list_item["list_id"], list_item["list_name"]
            if list_id in traffic:
                results_list.append(
                    {
                        "list_id": list_id,
                        "list_name": list_name,
                        "policy_name": name,
                    }
                )
                break
        if is_feature_enabled("port"):
            # Check for port usage
            if port in traffic:
                results_port.append(
                    {
                        "port": port,
                        "policy_name": name,
                        "traffic": traffic,
                    }
                )
            return results, results_list, results_port
    return results, results_list


@celery.task(bind=True, name="tasks.check_ip_across_lists_and_policies")
def check_ip_across_lists_and_policies(self, ip_str: str, port) -> dict:
    self.update_state(state="PROGRESS", meta={"step": "Starting", "percent": 0})
    print(ip_str)
    try:
        # Validate
        ip_network(ip_str, strict=False)
        self.update_state(
            state="PROGRESS", meta={"step": "Validated IPv4", "percent": 5}
        )

        # Scan lists
        self.update_state(
            state="PROGRESS", meta={"step": "Scanning lists", "percent": 10}
        )
        list_results = scan_cloudflare_lists(ip_str, API_TOKEN, ACC_ID)
        self.update_state(state="PROGRESS", meta={"step": "Lists done", "percent": 40})

        # Scan policies
        self.update_state(
            state="PROGRESS", meta={"step": "Scanning policies", "percent": 60}
        )
        
        if is_feature_enabled("port"):
            policy_results, policy_list_results, port_results = scan_cloudflare_policies(
                ip_str, API_TOKEN, ACC_ID, list_results, port
            )
        else:
            policy_results, policy_list_results = scan_cloudflare_policies(
                ip_str, API_TOKEN, ACC_ID, list_results
            )
        self.update_state(
            state="PROGRESS", meta={"step": "Policies done", "percent": 80}
        )

        # Finalize
        for r in policy_results + list_results + policy_list_results:
            print(r)
        self.update_state(state="PROGRESS", meta={"step": "Completed", "percent": 100})

        if not policy_results and not list_results:
            return {"message": "IPv4 not found in Zero Trust"}

        return {
            "message": {
                "policy": policy_results,
                "list": list_results,
                "policy_list": policy_list_results,
            }
        }

    except ValueError as e:
        logger.error(f"Invalid IP/CIDR: {e}")
        return {"message": "Invalid IPv4 address. Please try again."}
    except Exception as e:
        logger.error(f"Error: {e}")
        return {"message": str(e)}
