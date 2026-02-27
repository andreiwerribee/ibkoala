import json
import os
import time
import webbrowser
import requests
import boto3
from datetime import datetime, timezone
from Crypto.PublicKey import RSA     # only if using encryption key (rare for paper)
from Crypto.Cipher import PKCS1_v1_5
import base64
import hashlib
import hmac
import random

# ========================= CONFIG =========================
CONSUMER_KEY = os.getenv("IB_CONSUMER_KEY", "TESTCONS")   # change if you have custom
REALM = "test_realm"                                      # paper = test_realm, live = limited_poa
BASE_URL = "https://api.ibkr.com/v1/api"
SECRETS_NAME = "ibkoala/lst"
# ========================================================

secrets_client = boto3.client("secretsmanager")

def main():
    print("=== IBKOALA LST Refresh Script ===")
    
    # 1. Load or create previous tokens (for refresh)
    try:
        secret = json.loads(secrets_client.get_secret_value(SecretId=SECRETS_NAME)["SecretString"])
        access_token = secret.get("access_token")
        token_secret = secret.get("token_secret")
    except:
        access_token = token_secret = None
        print("No previous tokens – doing full initial auth")

    # 2. Get / refresh access token (OAuth 1.0a step)
    if not access_token:
        access_token, token_secret = full_oauth_flow()
    
    # 3. Compute Live Session Token via Diffie-Hellman
    lst_data = obtain_live_session_token(access_token, token_secret)
    
    # 4. (Optional but recommended) Call /tickle to get session cookie value
    session_token = call_tickle(lst_data["live_session_token"])
    
    # 5. Store everything in AWS Secrets Manager
    store_in_secrets(access_token, token_secret, lst_data, session_token)
    
    print("✅ LST refreshed and uploaded to Secrets Manager!")
    print(f"Expires: {datetime.fromtimestamp(lst_data['live_session_token_expiration']/1000)}")

# ====================== HELPER FUNCTIONS ======================

def full_oauth_flow():
    """Step-by-step OAuth 1.0a: request token → browser login → verifier → access token"""
    print("Opening browser for IB login...")
    
    # 1. Request token
    resp = requests.post(f"{BASE_URL}/oauth/request_token", params={
        "oauth_consumer_key": CONSUMER_KEY,
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": int(time.time()),
        "oauth_nonce": str(random.randint(10**8, 10**10)),
        "oauth_version": "1.0",
        "oauth_callback": "oob",                     # out-of-band = manual copy
        "realm": REALM
    })
    # Parse response (oauth_token + oauth_token_secret)
    # ... (standard parsing code – I can expand if needed)

    # 2. Open browser
    auth_url = f"https://www.interactivebrokers.com/authorize?oauth_token=..."
    webbrowser.open(auth_url)
    
    verifier = input("Paste the verifier code from the browser page: ").strip()
    
    # 3. Exchange for access token
    # ... (POST /oauth/access_token with verifier)
    return access_token, token_secret

def obtain_live_session_token(access_token, token_secret):
    """Diffie-Hellman + HMAC as per official IBKR spec"""
    # Generate DH challenge
    dh_random = random.getrandbits(256)
    prime = 0x...  # IBKR fixed prime (hardcoded in docs/repos)
    dh_challenge = hex(pow(2, dh_random, prime))[2:]
    
    payload = {
        "oauth_consumer_key": CONSUMER_KEY,
        "oauth_token": access_token,
        "diffie_hellman_challenge": dh_challenge,
        # + full OAuth signature parameters
    }
    
    resp = requests.post(f"{BASE_URL}/oauth/live_session_token", json=payload)
    data = resp.json()
    
    # Compute LST (exact math from docs)
    B = int(data["diffie_hellman_response"], 16)
    K = pow(B, dh_random, prime)
    # HMAC-SHA1 + prepend decrypt step (full 15-line calculation – included in final script)
    
    return {
        "live_session_token": lst_b64,
        "live_session_token_expiration": data["live_session_token_expiration"]
    }

def call_tickle(live_session_token):
    """Optional: Get the 'api' session cookie value"""
    headers = {"Authorization": f"OAuth oauth_token={live_session_token}"}
    resp = requests.post(f"{BASE_URL}/tickle", headers=headers)
    return resp.json()["session"]   # this is the value you put in cookie "api=..."

def store_in_secrets(access_token, token_secret, lst_data, session_token):
    secret_value = {
        "consumer_key": CONSUMER_KEY,
        "access_token": access_token,
        "token_secret": token_secret,
        "live_session_token": lst_data["live_session_token"],
        "session_token": session_token,          # the one used in cookie
        "expires_at": lst_data["live_session_token_expiration"] / 1000,
        "last_refresh": datetime.now(timezone.utc).isoformat()
    }
    secrets_client.put_secret_value(
        SecretId=SECRETS_NAME,
        SecretString=json.dumps(secret_value)
    )

if __name__ == "__main__":
    main()

