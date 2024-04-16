from flask import Flask, jsonify, redirect, url_for, request
import requests
import json
from datetime import datetime
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app) 

# CORS(app, resources={r"/api/*": {"origins": "http://localhost:3000"}})


def convert_unix_to_utc(unix_time):
    """Converts UNIX timestamp to a UTC datetime string."""
    return datetime.fromtimestamp(int(unix_time)).strftime('%Y-%m-%d %H:%M:%S')

GRAPHQL_URL = 'https://optimism.easscan.org/graphql'

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
            "id": '0x25eb07102ee3f4f86cd0b0c4393457965b742b8acc94aa3ddbf2bc3f62ed1381'
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
    

# Get the Schema's registered to DAO Registration factory by Attester Address
@app.route('/attestations/<attester_address>', methods=['GET'])
def get_attestations(attester_address):
    if not attester_address:
        return jsonify({"error": "Attester address is required."}), 400

    try:
        attestations_data = fetch_attestations(attester_address)

        # Check if the response from GraphQL is empty
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

            # Fetch and integrate schema details
            for i in range(len(array_fields["schemaUID"])):
                schema_id = array_fields['schemaUID'][i];
                schema_details = fetch_schema_details(schema_id) or {}
                print (schema_details)
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
                        "time": convert_unix_to_utc(schema_details.get("time", "")),
                        "txid": schema_details.get("txid", "")
                    }
                })

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
    """Fetches attestations for a given schema ID."""
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
        unique_attesters = {attestation['attester'] for attestation in raw_attestations}  # Use a set for unique addresses

        results = []

        for attester_address in unique_attesters:
            attester_response = get_attestations(attester_address)

            if attester_response.status_code == 200:
                attester_data = attester_response.get_json()
                attester_data['attesterAddress'] = attester_address  # Add attester address to the response data
                results.append(attester_data)
            else:
                results.append({
                    "error": f"Failed to fetch data for attester {attester_address}",
                    "statusCode": attester_response.status_code,
                    "attesterAddress": attester_address  # Include attester address even in case of error
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


# Redirect any other endpoint to '/'
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def catch_all(path):
    return redirect(url_for('get_home'))



if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
