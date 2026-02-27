import json
import os
import time
import boto3
from datetime import datetime, timezone
import requests
from botocore.exceptions import ClientError

# Environment variables (set via Lambda config, CDK, or Parameter Store)
IB_ACCOUNT_ID     = os.environ['IB_ACCOUNT_ID']           # e.g., 'DU1234567' or paper equiv
SECRETS_NAME      = os.environ['IB_LST_SECRET_NAME']      # 'ibkoala/lst'
DDB_TABLE_NAME    = os.environ['DDB_STATE_TABLE']         # 'IBKOALA-State'
EVENTBRIDGE_BUS   = os.environ.get('EVENT_BUS', 'default')
API_BASE_URL      = "https://api.ibkr.com/v1/api"         # Use https://api.ibkr.com/v1/portal for some paper envs if needed

# Global clients (reused on warm Lambda invocations)
secrets_client = boto3.client('secretsmanager')
dynamodb       = boto3.resource('dynamodb')
eventbridge    = boto3.client('events')
table          = dynamodb.Table(DDB_TABLE_NAME)

def lambda_handler(event, context):
    """
    IBKOALA Poller Lambda – every 5 seconds:
    - Load LST/session from Secrets Manager
    - Validate session
    - Fetch quotes, positions, trades
    - Detect changes vs previous state
    - Publish events to EventBridge
    - Update DynamoDB state
    """
    start_time = time.time()

    try:
        # 1. Load credentials from Secrets Manager (updated format)
        secret_data = get_secret_data()
        
        live_session_token = secret_data.get('live_session_token')
        session_token      = secret_data.get('session_token')  # from /tickle
        expires_at         = secret_data.get('expires_at', 0)

        if not session_token or time.time() > expires_at:
            raise ValueError(
                f"Session/LST expired (expires_at: {expires_at}). "
                "Run LST refresh script and update Secrets Manager."
            )

        # Common headers + cookies for authenticated requests
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        cookies = {
            'api': session_token   # This is the key: cookie name 'api' with tickle session value
        }

        # 2. Quick session validation (optional but recommended – prevents silent failures)
        if not validate_session(headers, cookies):
            raise RuntimeError("IBKR session invalid or terminated – refresh LST")

        # 3. Fetch data (use cookies + headers)
        quotes_data    = fetch_quotes(headers, cookies)
        positions_data = fetch_positions(headers, cookies, IB_ACCOUNT_ID)
        trades_data    = fetch_trades(headers, cookies)

        # 4. Load previous state
        prev_state = get_previous_state()

        # 5. Detect changes → build EventBridge entries
        events = detect_changes_and_build_events(
            quotes_data, positions_data, trades_data, prev_state
        )

        # 6. Publish if any events
        if events:
            publish_to_eventbridge(events)

        # 7. Save updated state
        save_new_state(quotes_data, positions_data, trades_data)

        duration = time.time() - start_time
        print(f"Poll success | Duration: {duration:.2f}s | Events: {len(events)}")

        return {'statusCode': 200, 'body': json.dumps({'events_count': len(events)})}

    except Exception as e:
        print(f"Poll failed: {str(e)}")
        # Future: Add SNS publish for alert on persistent failures
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

# ──────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ──────────────────────────────────────────────────────────────────────────────

def get_secret_data():
    """Fetch and parse the full secret JSON from Secrets Manager."""
    try:
        response = secrets_client.get_secret_value(SecretId=SECRETS_NAME)
        return json.loads(response['SecretString'])
    except ClientError as e:
        raise RuntimeError(f"Failed to get secret '{SECRETS_NAME}': {e}")

def validate_session(headers, cookies):
    """Quick check if session is alive via /tickle or /iserver/auth/status."""
    try:
        resp = requests.get(
            f"{API_BASE_URL}/tickle",
            headers=headers,
            cookies=cookies,
            timeout=5
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get('authenticated', False)  # or check 'iserver' fields
    except Exception as err:
        print(f"Session validation failed: {err}")
        return False

def fetch_quotes(headers, cookies):
    # Customize conids/fields for your symbols (EUR.USD, GBP.JPY, etc.)
    conids = "8314,8315"  # Example: EUR.USD, GBP.JPY – get real conids via /iserver/secdef/search
    params = f"?conids={conids}&fields=31,84,85,86,88"  # bid,ask,last,volume,...
    resp = requests.get(
        f"{API_BASE_URL}/iserver/marketdata/snapshot{params}",
        headers=headers,
        cookies=cookies
    )
    resp.raise_for_status()
    return resp.json()

def fetch_positions(headers, cookies, account_id):
    resp = requests.get(
        f"{API_BASE_URL}/portfolio/{account_id}/positions",
        headers=headers,
        cookies=cookies
    )
    resp.raise_for_status()
    return resp.json()

def fetch_trades(headers, cookies):
    resp = requests.get(
        f"{API_BASE_URL}/iserver/account/trades?days=1",
        headers=headers,
        cookies=cookies
    )
    resp.raise_for_status()
    return resp.json()

def get_previous_state():
    resp = table.get_item(Key={'pk': 'ibkoala_state'})
    return resp.get('Item', {}).get('data', {})

def detect_changes_and_build_events(quotes, positions, trades, prev):
    events = []
    # ── Positions open/close detection ──────────────────────────────────────
    prev_pos_map = {p.get('conid'): p for p in prev.get('positions', [])}
    curr_pos_map = {p.get('conid'): p for p in positions}

    for conid, pos in curr_pos_map.items():
        if conid not in prev_pos_map:
            events.append(build_event('position_opened', {'conid': conid, 'position': pos}))

    for conid in set(prev_pos_map) - set(curr_pos_map):
        events.append(build_event('position_closed', {'conid': conid, 'previous': prev_pos_map[conid]}))

    # ── Add similar logic for new trades, quote deltas > threshold, etc. ─────
    # Example stub for trades:
    # prev_trade_ids = {t['execution_id'] for t in prev.get('trades', [])}
    # for trade in trades:
    #     if trade['execution_id'] not in prev_trade_ids:
    #         events.append(build_event('new_trade', trade))

    return events

def build_event(detail_type, detail_dict):
    return {
        'Source': 'ibkoala.poller',
        'DetailType': detail_type,
        'Detail': json.dumps({
            **detail_dict,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }),
        'EventBusName': EVENTBRIDGE_BUS
    }

def publish_to_eventbridge(events):
    # Batch in groups of 10 (EventBridge limit)
    for i in range(0, len(events), 10):
        batch = events[i:i+10]
        eventbridge.put_events(Entries=batch)

def save_new_state(quotes, positions, trades):
    new_state = {
        'quotes': quotes,
        'positions': positions,
        'trades': trades,
        'last_poll_utc': datetime.now(timezone.utc).isoformat()
    }
    table.put_item(Item={
        'pk': 'ibkoala_state',
        'data': new_state
    })

