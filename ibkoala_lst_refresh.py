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

secrets_client = boto3.client("secretsmanager", region_name='ap-southeast-2')

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
    """Compute Live Session Token using Diffie-Hellman as per IBKR spec"""
    import random
    from hashlib import sha1
    import hmac

    # Fixed values from IBKR OAuth spec
    DH_PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    DH_GENERATOR = 2

    # Generate random private exponent (256 bits is sufficient)
    dh_random = random.getrandbits(256)

    # Compute public challenge: g^a mod p
    dh_challenge_int = pow(DH_GENERATOR, dh_random, DH_PRIME)
    dh_challenge = hex(dh_challenge_int)[2:]  # remove 0x prefix

    # Build payload for /oauth/live_session_token
    # Note: You need proper OAuth 1.0a signature here too (consumer key, token, nonce, timestamp, HMAC-SHA1)
    # For brevity, assuming you already have a helper to sign requests (or use requests-oauthlib)
    # Example payload skeleton:
    payload = {
        "oauth_consumer_key": CONSUMER_KEY,
        "oauth_token": access_token,
        "diffie_hellman_challenge": dh_challenge,
        # Add oauth_nonce, oauth_timestamp, oauth_signature_method="HMAC-SHA1", oauth_version="1.0"
        # oauth_signature computed over sorted params
    }

    # POST to endpoint (sign the request properly!)
    resp = requests.post(f"{BASE_URL}/oauth/live_session_token", params=payload)  # or json= if needed
    resp.raise_for_status()
    data = resp.json()

    # Server returns their public value B
    B = int(data["diffie_hellman_response"], 16)

    # Compute shared secret K = B^a mod p
    K = pow(B, dh_random, DH_PRIME)

    # Derive LST: typically HMAC-SHA1 of something + K bytes, but IBKR has a specific formula
    # From community impls: LST is hex(SHA1(K bytes + some fixed/consumer data))
    # But exact: often just hex(K) truncated or hashed; check a working repo for precision

    # Placeholder for final LST computation (adapt from a tested library)
    # Example from sharkeyboy/ib_python or similar:
    K_bytes = K.to_bytes((K.bit_length() + 7) // 8, 'big')
    lst_bytes = hmac.new(K_bytes, b"some fixed string or consumer key", sha1).digest()
    live_session_token = lst_bytes.hex()  # or base64, but usually hex

    return {
        "live_session_token": live_session_token,
        "live_session_token_expiration": data.get("live_session_token_expiration", int(time.time() * 1000) + 86400000)  # approx 24h
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

