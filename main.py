from flask import Flask, jsonify, redirect, url_for, request
import requests
import json
from datetime import datetime

app = Flask(__name__)

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

        # Check if the response from GraphQL is empty
        if not attestations_data:
            return jsonify({"message": "No attestations made by this Issuer"}), 404
      
        structured_attestations = []
        for attestation in attestations_data:
            decoded_data_list = json.loads(attestation['decodedDataJson'])
            non_array_fields = {
                "issuerName": "",
                "issuerDescription": "",
                "logo": "",
                "apiDocsURI": ""
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
    docs_html = """
    <h1>Welcome to the DAO Attestations API</h1>
    <p>This API provides structured attestation data for DAO issuers on the Optimism network.</p>
    <h2>Endpoints</h2>
    <ul>
        <li><b>/attestations/&lt;attester_address&gt;</b>: Fetch and return attestations for a given attester address.</li>
    </ul>
    <h2>Example Query</h2>
    <p>To fetch attestations for a specific attester address, you would use the following URL format:</p>
    <code>/attestations/0x88e50e06efB2B748E2B9670d2a6668237167382B</code>
    <p>This would return all attestations made by the issuer at the address <code>0x88e50e06efB2B748E2B9670d2a6668237167382B</code>.</p>
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
    app.run(debug=True)
