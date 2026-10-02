"""
Wazuh REST API client for PurpleOps.
Handles authentication and agent status queries against the Wazuh Manager API (port 55000).
"""

import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://localhost:55000")
API_USER = os.environ.get("WAZUH_API_USER", "wazuh")
API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD")


def _require_password():
    if not API_PASSWORD:
        raise RuntimeError(
            "WAZUH_API_PASSWORD is not set. Create a .env file (see .env.example) "
            "and load it, e.g.: export $(grep -v '^#' .env | xargs)"
        )


def get_token(timeout=10):
    _require_password()
    resp = requests.post(
        f"{WAZUH_API_URL}/security/user/authenticate",
        auth=(API_USER, API_PASSWORD),
        verify=False,
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()["data"]["token"]


def get_agents(token, timeout=10):
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{WAZUH_API_URL}/agents", headers=headers, verify=False, timeout=timeout)
    resp.raise_for_status()
    return resp.json()["data"]["affected_items"]


def get_agent_status(agent_id="001"):
    token = get_token()
    agents = get_agents(token)
    for a in agents:
        if a.get("id") == agent_id:
            return a
    return None


def get_manager_info(timeout=10):
    token = get_token(timeout=timeout)
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{WAZUH_API_URL}/", headers=headers, verify=False, timeout=timeout)
    resp.raise_for_status()
    return resp.json()["data"]


if __name__ == "__main__":
    info = get_manager_info()
    print("Wazuh API version:", info.get("api_version"))
    agent = get_agent_status("001")
    if agent:
        print(f"Agent 001 ({agent.get('name')}): status={agent.get('status')}, "
              f"os={agent.get('os', {}).get('name', 'unknown')}")
    else:
        print("Agent 001 not found.")
