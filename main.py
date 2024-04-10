from flask import Flask, request, jsonify
import requests
import json
from datetime import datetime

app = Flask(__name__)

GRAPHQL_URL = 'https://optimism.easscan.org/graphql'

# Updated fetch_attestations to accept an attester address
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
        print (response.json().get('data', {}).get('attestations', []))
        return response.json().get('data', {}).get('attestations', [])
    else:
        raise Exception(f"Query failed with status code {response.status_code}")

@app.route('/attestations/<attester_address>', methods=['GET'])
def get_attestations(attester_address):
    
    if not attester_address:
        return jsonify({"error": "Attester address is required as a query parameter."}), 400

    try:
        attestations_data = fetch_attestations(attester_address)
      
        structured_attestations = []
        for attestation in attestations_data:
            # Parse the decodedDataJson from string to list of dictionaries
            decoded_data_list = json.loads(attestation['decodedDataJson'])
            # Temporary storage for fields that are not arrays
            non_array_fields = {
                "issuerName": "",
                "issuerDescription": "",
                "logo": "",
                "apiDocsURI": ""
            }
            
            # Storage for array fields to process them separately
            array_fields = {
                "schemaUID": [],
                "schemaDescription": [],
                "networkID": []
            }
            
            for decoded_data_item in decoded_data_list:
                key_name = decoded_data_item['name']
                value = decoded_data_item['value']['value']

                # Separate handling for array and non-array fields
                if key_name in non_array_fields:
                    non_array_fields[key_name] = value
                elif key_name in array_fields and isinstance(value, list):
                    array_fields[key_name] = value

            # Assuming the arrays are of equal length, iterate through one array and use the index for the others
            for i in range(len(array_fields["schemaUID"])):
                structured_attestations.append({
                    "schemaUID": array_fields['schemaUID'][i],
                    "schemaDescription": array_fields['schemaDescription'][i],
                    "networkID": array_fields['networkID'][i],
                })

        structured_data = {
        "issuerName": non_array_fields['issuerName'],
        "issuerDescription": non_array_fields['issuerDescription'],
        "logo": non_array_fields['logo'],
        "apiDocsURI": non_array_fields['apiDocsURI'],
        "attestations": structured_attestations
        }

        response_schema = structured_data
        return jsonify(response_schema)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/', methods=['GET'])
def get_home():
     return "Welcome to DAO Attestations API"


if __name__ == '__main__':
    app.run(debug=True)
