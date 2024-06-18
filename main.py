import time
import logging
from flask import Flask, g, jsonify, redirect, url_for, request, Response
import requests
import orjson
from datetime import datetime
from flask_cors import CORS
import redis
import re
from eas_graphql_urls import EASGraphQLURLs
from schema_ids import SchemaIDs

class RequestTimingMiddleware:
    def __init__(self, app):
        self.app = app
        self.logger = logging.getLogger("RequestTimingMiddleware")
        self.logger.setLevel(logging.INFO)

        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
        self.logger.addHandler(handler)

        app.before_request(self.start_timer)
        app.after_request(self.log_request)

    def start_timer(self):
        g.start_time = time.time()

    def log_request(self, response):
        if not hasattr(g, 'start_time'):
            return response

        duration = time.time() - g.start_time
        self.logger.info(f"{request.method} {request.path} - {response.status_code} - {duration:.4f}s")
        return response

app = Flask(__name__)
CORS(app)
RequestTimingMiddleware(app)

redis_url = 'localhost'
r = redis.Redis(host=redis_url, port=6379, db=0, decode_responses=True)

urls = EASGraphQLURLs()

def test_redis():
    try:
        r.set('test_key', 'Hello, secure Redis!')
        value = r.get('test_key')
        print(f'The value of "test_key" is: {value}')
    except Exception as e:
        print(f"Failed to connect to Redis: {str(e)}")

test_redis()

try:
    response = r.ping()
    print("Redis is connected:", response)
except redis.exceptions.ConnectionError as e:
    print("Redis connection error:", str(e))

def add_daoip7_schema(schema_id: str):
    r.sadd("daoip7_schemas", schema_id)

def get_daoip7_schemas():
    return r.smembers("daoip7_schemas")

def hex_to_decimal(network_tuple: tuple) -> int:
    if network_tuple and isinstance(network_tuple, tuple) and len(network_tuple) > 0:
        network_dict = network_tuple[0]
        hex_value = network_dict.get('hex', '0x0')
        return int(hex_value, 16)
    return 0

def convert_network_id(network_id):
    try:
        if isinstance(network_id, dict) and 'hex' in network_id:
            return int(network_id['hex'], 16)  # Convert hex to int
        elif isinstance(network_id, int):
            return network_id  # Directly return the integer
        else:
            raise ValueError("Invalid networkID format")
    except Exception as e:
        app.logger.error(f"Error converting networkID: {network_id}, Error: {str(e)}")
        raise
    
    
def contains_word_context(schema_str: str) -> bool:
    return re.search(r'\bcontext\b', schema_str, re.IGNORECASE) is not None

def convert_unix_to_utc(unix_time: int) -> str:
    return datetime.fromtimestamp(unix_time).strftime('%Y-%m-%d %H:%M:%S')

DAO_REGISTRY_SCHEMA = '0x25eb07102ee3f4f86cd0b0c4393457965b742b8acc94aa3ddbf2bc3f62ed1381'

def populate_daoip7_compliant_schemas(schema_id: str, network_id: int = 10) -> list:
    url = urls.get_url_by_network_id(network_id)
    query = '''
    query Schema($where: SchemaWhereUniqueInput!) {
      schema(where: $where) {
        attestations {
          decodedDataJson
        }
      }
    }
    '''
    variables = {"where": {"id": schema_id}}

    try:
        response = requests.post(url, json={'query': query, 'variables': variables}, headers={"Content-Type": "application/json"})
        if response.status_code == 200:
            try:
                json_response = response.json()
            except requests.exceptions.JSONDecodeError as e:
                app.logger.error(f"Failed to decode JSON response: {str(e)}")
                return []

            data = json_response.get('data', {})
            if not data or 'schema' not in data or not data['schema'].get('attestations'):
                app.logger.info(f"No valid data or attestations found for schema ID {schema_id} on network {network_id}")
                return []

            attestations = data['schema']['attestations']
            daoip7_schemas = extract_daoip7_schemas(attestations)
            schemas = get_daoip7_schemas()
            return schemas
        else:
            app.logger.error(f"Request failed with status code {response.status_code}")
            return []
    except requests.exceptions.RequestException as e:
        app.logger.error(f"HTTP request exception: {str(e)}")
        return []

def extract_daoip7_schemas(attestations: list) -> list:
    unique_schemas = set()
    for attestation in attestations:
        decoded_data_json = orjson.loads(attestation['decodedDataJson'])
        for item in decoded_data_json:
            if item['name'] == 'schemaId':
                unique_schemas.add(item['value']['value'])
                add_daoip7_schema(item['value']['value'])
    return list(unique_schemas)

context_schema_id = "0xcc6c9b07bfccd15c8f313d23bf4389fb75629a620c5fa669c898bf1e023f2508"
daoip7_schemas = populate_daoip7_compliant_schemas(context_schema_id, 10)
print("DAOIP7 Compliant Schema IDs populated of OP network:", daoip7_schemas)

def fetch_attestations(attester_address: str, networkId: int = 10) -> list:
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
        urls.get_url_by_network_id(networkId),
        json={'query': query, 'variables': variables},
        headers={"Content-Type": "application/json"}
    )
    if response.status_code == 200:
        data = response.json()
        if data and 'data' in data and 'attestations' in data['data']:
            print("fetch attestations Success")
            return data['data']['attestations']
        else:
            app.logger.error("Data is missing 'attestations' key or is malformed: {}".format(data))
            print("Data is missing 'attestations' key or is malformed: {}".format(data))
            return []
    else:
        app.logger.error("Failed to fetch data with status code {}".format(response.status_code))
        print("Failed to fetch data with status code {}".format(response.status_code))
        return []

def fetch_schema_details(schema_id: str, networkId: int = 10) -> dict:
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
        urls.get_url_by_network_id(networkId),
        json={'query': query, 'variables': variables},
        headers={"Content-Type": "application/json"}
    )
    if response.status_code == 200:
        data = response.json().get('data', {}).get('schema', {})
        if not data:
            print(f"No data returned for schema ID {schema_id}")
            return {}
        return data
    else:
        raise Exception(f"fetch_schema_details Query failed with status code {response.status_code}")

@app.route('/attestations/<attester_address>', methods=['GET'])
def get_attestations(attester_address: str):
    if not attester_address:
        return Response(orjson.dumps({"error": "Attester address is required."}), mimetype='application/json'), 400

    try:
        attestations_data = fetch_attestations(attester_address)
        # app.logger.debug(f"Attestations Data: {attestations_data}")
        if not attestations_data:
            return Response(orjson.dumps({"message": "No attestations made by this Issuer"}), mimetype='application/json'), 404

        structured_schemas_by_attester = []
        for attestation in attestations_data:
            try:
                decoded_data_list = orjson.loads(attestation['decodedDataJson'])
                if not isinstance(decoded_data_list, list):
                    app.logger.error(f"Expected list but got {type(decoded_data_list)}: {decoded_data_list}")
                    continue
            except Exception as e:
                app.logger.error(f"Error parsing 'decodedDataJson': {str(e)}")
                continue

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
                try:
                    key_name = decoded_data_item['name']
                    value = decoded_data_item['value']['value']
                    
                    # app.logger.debug(f"Processing key: {key_name}, Value: {value}")

                    if key_name in non_array_fields:
                        if not isinstance(value, str):
                            raise TypeError(f"Expected str for {key_name}, got {type(value)}")
                        non_array_fields[key_name] = value
                    elif key_name in array_fields and isinstance(value, list):
                        array_fields[key_name].extend(value)
                except (KeyError, TypeError) as e:
                    app.logger.error(f"Error processing item {decoded_data_item}: {str(e)}")
                    continue

            for i in range(len(array_fields["schemaUID"])):
                schema_id = array_fields['schemaUID'][i]
                try:
                    network_id = int(array_fields['networkID'][i]['hex'], 16)
                except Exception as e:
                    app.logger.error(f"Error converting networkID: {array_fields['networkID'][i]}, Error: {str(e)}")
                    continue
                
                schema_details = fetch_schema_details(schema_id, network_id) or {}
                # app.logger.debug(f"Schema Details: {schema_details}")
                

                if not schema_details:
                    continue

                # This section assumes you have defined `populate_daoip7_compliant_schemas` and `contains_word_context`.
                if schema_id in populate_daoip7_compliant_schemas(schema_id, network_id):
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
                    schema_text = schema_details.get("schema", "{}")
                    if contains_word_context(schema_text):
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
                        continue

        structured_data = {
            "issuerName": non_array_fields['issuerName'],
            "issuerDescription": non_array_fields['issuerDescription'],
            "logo": non_array_fields['logo'],
            "apiDocsURI": non_array_fields['apiDocsURI'],
            "schemas": structured_schemas_by_attester,
        }

        return Response(orjson.dumps(structured_data), mimetype='application/json'), 200
    except Exception as e:
        app.logger.error(f"Error in get_attestations: {str(e)}")
        print(e)
        return Response(orjson.dumps({"error in get_attestations": str(e)}), mimetype='application/json'), 500



def fetch_schema_attestations(schema_id: str, network_id: int = 10) -> list:
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
    url = urls.get_url_by_network_id(network_id)
    response = requests.post(
        url,
        json={'query': query, 'variables': variables},
        headers={"Content-Type": "application/json"}
    )
    # app.logger.debug(f"Request URL: {url}")
    # app.logger.debug(f"Request Payload: {response.request.body}")
    # app.logger.debug(f"Response Status: {response.status_code}")
    # app.logger.debug(f"Response Body: {response.text}")

    if response.status_code == 200:
        return response.json().get('data', {}).get('schema', {}).get('attestations', [])
    else:
        raise Exception(f"fetch_schema_attestations Query failed with status code {response.status_code}")

@app.route('/schema_attestations/<schema_id>', methods=['GET'])
def get_schema_attestations(schema_id: str):
    try:
        raw_attestations = fetch_schema_attestations(schema_id)
        daoip7_schemas = populate_daoip7_compliant_schemas(schema_id)  # Ensure context_schema_id is replaced with schema_id if that's what you meant
        unique_attesters = {attestation['attester'] for attestation in raw_attestations}

        results = []

        for attester_address in unique_attesters:
            attester_response, status_code = get_attestations(attester_address)
            if status_code == 200:
                # Extract JSON data from the Response object
                attester_data = attester_response.get_json()

                if not isinstance(attester_data, dict):
                    attester_data = attester_data[0]

                if 'schemas' not in attester_data:
                    continue

                attester_data['schemas'] = [
                    schema for schema in attester_data['schemas']
                    if schema['schemaDetails']['creator'] == attester_address
                ]

                if not attester_data['schemas']:
                    continue

                attester_data['attesterAddress'] = attester_address
                results.append(attester_data)
            else:
                results.append({
                    "error": f"Failed to fetch data for attester {attester_address}",
                    "statusCode": status_code,
                    "attesterAddress": attester_address
                })

        return Response(orjson.dumps(results), mimetype='application/json'), 200
    except Exception as e:
        return Response(orjson.dumps({"error in get_schema_attestations": str(e)}), mimetype='application/json'), 500

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
    get_attestations('0x88e50e06efB2B748E2B9670d2a6668237167382B')
