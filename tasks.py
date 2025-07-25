import os
import requests
import re
from celery import Celery
from ipaddress import ip_address, ip_network

# Initialize Celery
celery = Celery('tasks')
celery.config_from_object('celeryconfig')

# Cloudflare creds
API_TOKEN = os.getenv('CLOUDFLARE_API_TOKEN')
ACC_ID    = os.getenv('CLOUDFLARE_ACCOUNT_ID')
# Define excluded CIDRs
excluded_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]


def is_ip_in_cidr(ip, cidr):
    return ip_address(ip) in ip_network(cidr)


def is_ip_excluded(ip_or_cidr):
    try:
        ip_net = ip_network(ip_or_cidr, strict=False)
    except ValueError:
        return False  # Invalid IP/CIDR, treat as not excluded

    for excluded in excluded_cidrs:
        excluded_net = ip_network(excluded)
        if ip_net.subnet_of(excluded_net) and ip_net.prefixlen <= excluded_net.prefixlen:
            return True  # Exclude only if it's not more specific
    return False


def scan_cloudflare_lists(ip, api_token, account_id):
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    # Get lists
    lists_url = (
        f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway/lists"
    )
    lists_response = requests.get(lists_url, headers=headers)
    lists_data = lists_response.json()
    results = []
    # Scan lists
    for list_item in lists_data["result"]:
        list_name = list_item["name"]
        list_id = list_item["id"]
        # Filter to only look in IP Address lists
        if list_item["type"].upper() != "IP":
            continue
        # Get list entries
        list_entries_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway/lists/{list_id}/items"
        list_entries_response = requests.get(list_entries_url, headers=headers)
        list_entries_data = list_entries_response.json()
        for entry in list_entries_data["result"]:
            if is_ip_in_cidr(ip, entry["value"]) and not is_ip_excluded(entry["value"]):
                results.append(f"IP {ip} found in list: {list_name}")
    return results


def scan_cloudflare_policies(ip, api_token, account_id):
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    # Get policies
    policies_url = (
        f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway/rules"
    )
    policies_response = requests.get(policies_url, headers=headers)
    policies_data = policies_response.json()
    results = []
    # Scan policies
    for policy_item in policies_data["result"]:
        policy_name = policy_item["name"]
        traffic_data = policy_item.get("traffic", "")
        # Perform string search for IP or CIDR
        if re.search(r"\b" + re.escape(ip) + r"\b", traffic_data):
            results.append(f"IP {ip} found in policy: {policy_name}")
        else:
            # Check if any CIDR in the traffic data contains the IP
            for cidr in re.findall(
                r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", traffic_data
            ):
                if is_ip_in_cidr(ip, cidr) and not is_ip_excluded(cidr):
                    results.append(f"IP {ip} found in policy: {policy_name}")
                    break
    return results


@celery.task(bind=True, name='tasks.check_ip_across_lists_and_policies')
def check_ip_across_lists_and_policies(self, ip_str: str, ) -> dict:
    self.update_state(state='PROGRESS', meta={'step': 'Starting', 'percent': 0})
    try:
        # Try parsing as a network (CIDR or single IP)
        ip_network(ip_str, strict=False)
        # Scan and print results
        self.update_state(state='PROGRESS', meta={'step': 'scan_cloudflare_policies', 'percent': 33})
        PolicyResults = scan_cloudflare_policies(ip_str, API_TOKEN, ACC_ID)
        self.update_state(state='PROGRESS', meta={'step': 'scan_cloudflare_lists', 'percent': 66})
        ListResults = scan_cloudflare_lists(ip_str, API_TOKEN, ACC_ID)
        for result in PolicyResults:
            print(result)
        for result in ListResults:
            print(result)
        self.update_state(state='PROGRESS',meta={'step': 'processing results', 'percent': 90 })
        return {
            'message': { 
            'policy': PolicyResults,
            'list':   ListResults
            }
        }
    except ValueError:
        print(ValueError)
        return {"message": "Invalid IPv4 address. Please try again."}
