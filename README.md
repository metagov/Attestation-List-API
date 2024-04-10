# DAO Attestations API
###### A DAOstar Project

The DAO Attestations API is a Flask-based web service designed to fetch and serve attestation data from the Optimism network's GraphQL endpoint. It allows clients to retrieve structured attestation data for a given attester address via a clean and simple REST API.

## Features

- Fetch attestation data using an attester's Ethereum address.
- Structure and serve attestation data in a JSON format.
- Handle requests to a GraphQL API to fetch raw attestation data.

## Installation

To set up the DAO Attestations API on your local machine, follow these steps:

### Prerequisites

- Python 3.6 or later
- pip (Python package manager)

### Steps

1. **Clone the repository**

   ```bash
   git clone https://github.com/metagov/Attestation-List-API
   cd Attestation-List-API
   ```

2. **Set up a virtual environment (optional but recommended)**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**

   ```bash
   python main.py
   ```

   The API will be accessible at `http://127.0.0.1:5000/`.

## Usage

### Endpoints

- **Get Attestations for an Attester Address**

  **Request:**

  `GET /attestations/<attester_address>`

  **Response:**

  - **200 OK** - Returns structured attestation data for the specified attester address.
  - **400 Bad Request** - If the attester address is not provided or invalid.
  - **500 Internal Server Error** - If there was an error processing the request.

- **Home**

  **Request:**

  `GET /`

  **Response:**

  - **200 OK** - Returns a welcome message.

### Examples

- **Fetching Attestations**

  ```bash
  curl http://127.0.0.1:5000/attestations/0x88e50e06efB2B748E2B9670d2a66682371673888
  ```

## Development

To contribute to the development of the DAO Attestations API, you can start by checking out our issue tracker or feature requests. Ensure to follow the project's code style and contribute guidelines.

## Support

For support, please open an issue in the GitHub repository or contact the repository owner.

## License

This project is licensed under the [MIT License](LICENSE.md).
