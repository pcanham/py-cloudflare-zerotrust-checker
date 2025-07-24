import os
import requests
from celery import Celery
from ipaddress import ip_address, ip_network

# Initialize Celery
celery = Celery('tasks')
celery.config_from_object('celeryconfig')

# Cloudflare creds
API_TOKEN = os.getenv('CLOUDFLARE_API_TOKEN')
ACC_ID    = os.getenv('CLOUDFLARE_ACCOUNT_ID')

HEADERS = {
    'Authorization': f'Bearer {API_TOKEN}',
    'Content-Type': 'application/json'
}

# RFC1918 networks
PRIVATE_NETWORKS = [
    ip_network('10.0.0.0/8'),
    ip_network('172.16.0.0/12'),
    ip_network('192.168.0.0/16'),
]

def is_private(ip_str: str) -> bool:
    ip = ip_address(ip_str)
    return any(ip in net for net in PRIVATE_NETWORKS)

@celery.task(bind=True, name='tasks.check_ip_across_zero_trust_and_policies')
def check_ip_across_zero_trust_and_policies(self, ip_str: str) -> dict:
    """
    For a given IP:
      1) Iterate all Zero Trust lists, checking membership
      2) Fetch all Gateway policies and match src_ip/CIDRs
    """
    if is_private(ip_str):
        return {'error': 'IP is within RFC1918 private range'}

    # 1) Zero Trust lists
    lists_url = f'https://api.cloudflare.com/client/v4/accounts/{ACC_ID}/gateway/lists'
    resp = requests.get(lists_url, headers=HEADERS)
    resp.raise_for_status()
    zt_lists = resp.json().get('result', [])

    total = len(zt_lists)
    self.update_state(state='PROGRESS', meta={'step': 'fetching_zero_trust_lists', 'total_lists': total})

    lists_summary = []
    for idx, zt in enumerate(zt_lists, start=1):
        list_id   = zt['id']
        list_name = zt.get('name')

        # progress update
        self.update_state(
            state='PROGRESS',
            meta={
                'step': 'checking_list',
                'current_list_index': idx,
                'list_name': list_name
            }
        )

        items_url = f'https://api.cloudflare.com/client/v4/accounts/{ACC_ID}/gateway/lists/{list_id}/items'
        items_resp = requests.get(items_url, headers=HEADERS, params={'match': ip_str})
        items_resp.raise_for_status()
        items = items_resp.json().get('result', [])

        lists_summary.append({
            'list_id':   list_id,
            'list_name': list_name,
            'matched':   bool(items),
            'items':     items
        })

    # 2) Gateway policies
    self.update_state(state='PROGRESS', meta={'step': 'fetching_policies'})
    policies_url = f'https://api.cloudflare.com/client/v4/accounts/{ACC_ID}/gateway/policies'
    pol_resp = requests.get(policies_url, headers=HEADERS)
    pol_resp.raise_for_status()
    policies = pol_resp.json().get('result', [])

    matched_policies = []
    for p in policies:
        # assume policy has src_ip or src_cidr fields (adjust if your schema differs)
        cidrs = p.get('src_ip', []) + p.get('src_cidr', [])
        for cidr in cidrs:
            if ip_address(ip_str) in ip_network(cidr):
                matched_policies.append({
                    'policy_id':   p.get('id'),
                    'policy_name': p.get('name'),
                    'matched_cidr': cidr
                })
                break

    return {
        'ip':               ip_str,
        'zero_trust_lists': lists_summary,
        'gateway_policies': matched_policies
    }
