from flask import Flask, jsonify, redirect, url_for, request
import requests
import json
from datetime import datetime
from flask_cors import CORS
import redis
import re

app = Flask(__name__)
CORS(app)
redis_url = 'redis://red-cp1lchmct0pc73d37gl0:6379'
r = redis.Redis.from_url(redis_url, db=0, decode_responses=True)

# redis_url = 'localhost'
# r = redis.Redis(host=redis_url, port=6379, db=0, decode_responses=True)
def test_redis():
    try:
        # Setting a key
        r.set('test_key', 'Hello, secure Redis!')
        # Getting a key
        value = r.get('test_key')
        print(f'The value of "test_key" is: {value}')
    except Exception as e:
        print(f"Failed to connect to Redis: {str(e)}")

# Call the test function
test_redis()

try:
    response = r.ping()
    print("Redis is connected:", response)
except redis.exceptions.ConnectionError as e:
    print("Redis connection error:", str(e))

def add_daoip7_schema(schema_id):
    """Add a new schema ID to the Redis set of DAOIP7 compliant schemas."""
    r.sadd("daoip7_schemas", schema_id)

def get_daoip7_schemas():
    """Retrieve all DAOIP7 compliant schema IDs."""
    return r.smembers("daoip7_schemas")

def contains_word_context(schema_str):
    return re.search(r'\bcontext\b', schema_str, re.IGNORECASE) is not None


def convert_unix_to_utc(unix_time):
    """Converts UNIX timestamp to a UTC datetime string."""
    return datetime.fromtimestamp(int(unix_time)).strftime('%Y-%m-%d %H:%M:%S')

GRAPHQL_URL = 'https://optimism.easscan.org/graphql'
DAO_REGISTRY_SCHEMA = '0x25eb07102ee3f4f86cd0b0c4393457965b742b8acc94aa3ddbf2bc3f62ed1381'

def populate_daoip7_compliant_schemas(schema_id):
    """Fetch attestations for a given schema ID and populate a list with DAOIP7 compliant schema IDs from decoded JSON."""
    url = 'https://optimism.easscan.org/graphql'  # Replace with the actual GraphQL endpoint if different
    query = '''
    query Schema($where: SchemaWhereUniqueInput!) {
      schema(where: $where) {
        attestations {
          decodedDataJson
        }
      }
    }
    '''
    variables = {
        "where": {
            "id": schema_id
        }
    }

    response = requests.post(url, json={'query': query, 'variables': variables}, headers={"Content-Type": "application/json"})
    if response.status_code == 200:
        data = response.json().get('data', {}).get('schema', {}).get('attestations', [])
        daoip7_schemas = extract_daoip7_schemas(data)
        schemas = get_daoip7_schemas()
        return schemas
    else:
        raise Exception(f"Failed to fetch data with status code {response.status_code}")

def extract_daoip7_schemas(attestations):
    """Extract unique DAOIP7 compliant schema IDs from a list of attestations."""
    unique_schemas = set()
    for attestation in attestations:
        decoded_data_json = json.loads(attestation['decodedDataJson'])
        for item in decoded_data_json:
            if item['name'] == 'schemaId':
                unique_schemas.add(item['value']['value'])
                add_daoip7_schema(item['value']['value'])
    return list(unique_schemas)

# Example usage:
context_schema_id = "0xcc6c9b07bfccd15c8f313d23bf4389fb75629a620c5fa669c898bf1e023f2508" #Context schema on OP Mainnet
daoip7_schemas = populate_daoip7_compliant_schemas(context_schema_id)
print("DAOIP7 Compliant Schema IDs:", daoip7_schemas)


def fetch_attestations(attester_address):
    query = '''
    query Attestations($attesterAddress: [String!]) {
      attestations(where: {
        schemaId: { equals: "0x25eb07102ee3f4f86cd0b0c4393457965b742b8acc94aa3ddbf2bc3f62ed1381" },
        attester: { in: $attesterAddress }
      }) {
        id
        decodedDataJson
      }
    }
    '''
    variables = {
        "attesterAddress": [attester_address]
    }
    response = requests.post(
        GRAPHQL_URL,
        json={'query': query, 'variables': variables},
        headers={"Content-Type": "application/json"}
    )
    if response.status_code == 200:
        print("200 OK")
        return response.json().get('data', {}).get('attestations', [])
    else:
        raise Exception(f"Query failed with status code {response.status_code}")

def fetch_schema_details(schema_id):
    query = '''
    query Schema($schemaWhere2: SchemaWhereUniqueInput!) {
      schema(where: $schemaWhere2) {
        creator
        id
        resolver
        revocable
        schema
        _count {
          attestations
        }
        time
        txid
      }
    }
    '''
    variables = {
        "schemaWhere2": {
            "id": schema_id
        }
    }
    response = requests.post(
        GRAPHQL_URL,
        json={'query': query, 'variables': variables},
        headers={"Content-Type": "application/json"}
    )
    if response.status_code == 200:
        return response.json().get('data', {}).get('schema', {})
    else:
        raise Exception(f"Query failed with status code {response.status_code}")

@app.route('/attestations/<attester_address>', methods=['GET'])
def get_attestations(attester_address):
    if not attester_address:
        return jsonify({"error": "Attester address is required."}), 400

    try:
        attestations_data = fetch_attestations(attester_address)
        daoip7_schemas = populate_daoip7_compliant_schemas(context_schema_id)


        if not attestations_data:
            return jsonify({"message": "No attestations made by this Issuer"}), 404

        structured_schemas_by_attester = []
        for attestation in attestations_data:
            decoded_data_list = json.loads(attestation['decodedDataJson'])
            non_array_fields = {
                "issuerName": "",
                "issuerDescription": "",
                "logo": "",
                "apiDocsURI": "",
                "attesterAddress": ""
            }

            array_fields = {
                "schemaUID": [],
                "schemaDescription": [],
                "networkID": []
            }

            for decoded_data_item in decoded_data_list:
                key_name = decoded_data_item['name']
                value = decoded_data_item['value']['value']

                if key_name in non_array_fields:
                    non_array_fields[key_name] = value
                elif key_name in array_fields and isinstance(value, list):
                    array_fields[key_name].extend(value)

            for i in range(len(array_fields["schemaUID"])):
                schema_id = array_fields['schemaUID'][i]
                schema_details = fetch_schema_details(schema_id) or {}
                
                if not schema_details:  # Skip if schema_details is empty
                    continue  
                schema_text = schema_details.get("schema", "{}")
                if schema_id in daoip7_schemas: # Context set check                
                    structured_schemas_by_attester.append({
                        "schemaUID": array_fields['schemaUID'][i],
                        "schemaDescription": array_fields['schemaDescription'][i],
                        "networkID": array_fields['networkID'][i],
                        "schemaDetails": {
                            "creator": schema_details.get("creator", ""),
                            "id": schema_details.get("id", ""),
                            "resolver": schema_details.get("resolver", ""),
                            "revocable": schema_details.get("revocable", False),
                            "schema": schema_details.get("schema", ""),
                            "attestationsCount": schema_details.get("_count", {}).get("attestations", 0),
                            "time": convert_unix_to_utc(schema_details.get("time", 0)),
                            "txid": schema_details.get("txid", "")
                        }
                    })
                else:
                    if contains_word_context(schema_text):
                        structured_schemas_by_attester.append({
                            "schemaUID": schema_id,
                            "schemaDescription": array_fields['schemaDescription'][i],
                            "networkID": array_fields['networkID'][i],
                            "schemaDetails": {
                                "creator": schema_details.get("creator", ""),
                                "id": schema_details.get("id", ""),
                                "resolver": schema_details.get("resolver", ""),
                                "revocable": schema_details.get("revocable", False),
                                "schema": schema_details.get("schema", ""),
                                "attestationsCount": schema_details.get("_count", {}).get("attestations", 0),
                                "time": convert_unix_to_utc(schema_details.get("time", 0)),
                                "txid": schema_details.get("txid", "")
                            }
                        })
                    else:
                        continue  # Optionally handle cases where 'context' is not found

        structured_data = {
            "issuerName": non_array_fields['issuerName'],
            "issuerDescription": non_array_fields['issuerDescription'],
            "logo": non_array_fields['logo'],
            "apiDocsURI": non_array_fields['apiDocsURI'],
            "schemas": structured_schemas_by_attester,
        }

        return jsonify(structured_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def fetch_schema_attestations(schema_id):
    query = '''
    query ($schemaWhere2: SchemaWhereUniqueInput!) {
      schema(where: $schemaWhere2) {
        attestations {
          attester
        }
      }
    }
    '''
    variables = {"schemaWhere2": {"id": schema_id}}
    response = requests.post(
        GRAPHQL_URL,
        json={'query': query, 'variables': variables},
        headers={"Content-Type": "application/json"}
    )
    if response.status_code == 200:
        return response.json().get('data', {}).get('schema', {}).get('attestations', [])
    else:
        raise Exception(f"Query failed with status code {response.status_code}")

@app.route('/schema_attestations/<schema_id>', methods=['GET'])
def get_schema_attestations(schema_id):
    try:
        raw_attestations = fetch_schema_attestations(schema_id)
        daoip7_schemas = populate_daoip7_compliant_schemas(context_schema_id)
        unique_attesters = {attestation['attester'] for attestation in raw_attestations}

        results = []

        for attester_address in unique_attesters:
            attester_response = get_attestations(attester_address)

            if attester_response.status_code == 200:
                attester_data = attester_response.get_json()

                # Filter schemas to include only those where the creator matches the attester address
                attester_data['schemas'] = [
                    schema for schema in attester_data['schemas']
                    if schema['schemaDetails']['creator'] == attester_address
                ]

                # Check if there are valid schemas after filtering; if not, continue to the next attester
                if not attester_data['schemas']:
                    continue

                attester_data['attesterAddress'] = attester_address
                results.append(attester_data)
            else:
                results.append({
                    "error": f"Failed to fetch data for attester {attester_address}",
                    "statusCode": attester_response.status_code,
                    "attesterAddress": attester_address
                })

        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/', methods=['GET'])
def get_home():
    docs_html = """
    <h1>Welcome to the DAO Attestations API</h1>
    <p>This API provides structured attestation data for DAO issuers on the Optimism network.</p>
    <h2>Endpoints</h2>
    <ul>
        <li><b>/attestations/&lt;attester_address&gt;</b>: Fetch and return attestations for a given attester address. Returns detailed information about each attestation, including issuer information and schema details.</li>
        <li><b>/schema_attestations/&lt;schema_id&gt;</b>: Fetch and return all unique attestations for a specific schema ID. This endpoint ensures that each attester is processed only once, even if they appear multiple times in the schema's attestations.</li>
    </ul>
    <h2>Example Queries</h2>
    <p>To fetch attestations for a specific attester address, you would use the following URL format:</p>
    <code>/attestations/0x88e50e06efB2B748E2B9670d2a6668237167382B</code>
    <p>This would return all attestations made by the issuer at the address <code>0x88e50e06efB2B748E2B9670d2a6668237167382B</code>.</p>
    <p>To fetch all unique attestations for a specific schema ID, use the following URL format:</p>
    <code>/schema_attestations/0x25eb07102ee3f4f86cd0b0c4393457965b742b8acc94aa3ddbf2bc3f62ed1381</code>
    <p>This endpoint will process each attester only once, returning a list of attestations associated with the given schema ID.</p>
    <p>Refer to the GitHub repository for more detailed documentation: <a href='https://github.com/metagov/Attestation-List-API'>Attestations List API by DAOstar</a></p>
    ---
    <h5><a href='https://daostar.org'>A DAOstar Project</a></h5>
    """
    return docs_html

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def catch_all(path):
    return redirect(url_for('get_home'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)