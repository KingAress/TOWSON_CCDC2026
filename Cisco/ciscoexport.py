# fmc_export.py
import requests
import json
FMC_IP = "172.242."
USERNAME = "admin"
PASSWORD = "67!DeadbeatMandy"
def get_auth_token():
    url = f"https://{FMC_IP}/api/fmc_platform/v1/auth/generatetoken"
    response = requests.post(url, auth=(USERNAME, PASSWORD), verify=False)
    token = response.headers["X-auth-access-token"]
    domain_uuid = response.headers["DOMAIN_UUID"]
    return token, domain_uuid

def export_fmc_policies():
    token, domain_uuid = get_auth_token()
    headers = {
        "X-auth-access-token": token,
        "Content-Type": "application/json"
    }
    
    url = f"https://{FMC_IP}/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies"
    resp = requests.get(url, headers=headers, verify=False)
    policies = resp.json()["items"]

    for policy in policies:
        policy_id = policy["id"]
        policy_name = policy["name"]
        rules_url = f"https://{FMC_IP}/api/fmc_config/v1/domain/{domain_uuid}/policy/accesspolicies/{policy_id}/accessrules?limit=1000"
        rules_resp = requests.get(rules_url, headers=headers, verify=False)
        rules = rules_resp.json()
    
    with open(f"fmc_policy_{policy_name}.json", "w") as f:
        json.dump(rules, f, indent=2)
    
    print(f"Exported policy {policy_name} to fmc_policy_{policy_name}.json")

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    export_fmc_policies()