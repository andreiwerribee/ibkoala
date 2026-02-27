import json
import boto3
from ibind import IbkrClient, IbkrWsClient, OAuth1aConfig

# Config
CONSUMER_KEY = "TESTCONS"  # or your actual key for paper
REALM = "test_realm"       # for paper/demo
SECRETS_NAME = "ibkoala/lst"

secrets_client = boto3.client("secretsmanager")

# Headless-ish OAuth (ibind supports verifier prompt or full flow)
oauth_client = IbkrOAuthClient(consumer_key=CONSUMER_KEY, realm=REALM)

# This may open browser or give URL – follow ibind wiki for exact flow
print("Follow instructions to authenticate (may open browser)...")
access_token_data = oauth_client.authenticate()  # or .login_flow() etc. – check docs

# Create main client with authenticated session
ib_client = IbkrClient(oauth_client=oauth_client)

# Optional: Force a /tickle or /iserver/auth/status to confirm and get session details
ib_client.tickle()  # refreshes/validates session

# Extract useful tokens (ibind manages internally, but you can access)
# ibind often stores session in its internal state; pull what you need
session_info = {
    "access_token": oauth_client.access_token,
    "token_secret": oauth_client.token_secret,
    # If ibind exposes live_session_token or session cookie value:
    "live_session_token": getattr(oauth_client, 'live_session_token', None),
    "session_token": ib_client.session_token if hasattr(ib_client, 'session_token') else None,  # check actual attr
    "expires_at": time.time() + 86400,  # approx 24h; get real from response if available
    "last_refresh": datetime.now(timezone.utc).isoformat()
}

# Upload to Secrets Manager
secrets_client.put_secret_value(
    SecretId=SECRETS_NAME,
    SecretString=json.dumps(session_info)
)

print("LST / session refreshed and saved to AWS Secrets Manager!")