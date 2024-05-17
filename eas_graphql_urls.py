class EASGraphQLURLs:
    def __init__(self):
        self.networks = {
            "ethereum": {
                "url": "https://easscan.org/graphql",
                "network_id": 1
            },
            "ethereum_sepolia": {
                "url": "https://sepolia.easscan.org/graphql",
                "network_id": 11155111
            },
            "arbitrum": {
                "url": "https://arbitrum.easscan.org/graphql",
                "network_id": 42161
            },
            "base": {
                "url": "https://base.easscan.org/graphql",
                "network_id": 2001
            },
            "base_goerli": {
                "url": "https://base-goerli.easscan.org/graphql",
                "network_id": 5
            },
            "linea": {
                "url": "https://linea.easscan.org/graphql",
                "network_id": 777
            },
            "optimism": {
                "url": "https://optimism.easscan.org/graphql",
                "network_id": 10
            },
        }

    def __getitem__(self, key):
        """Allows dictionary-like access"""
        return self.networks.get(key, "Network not found")

    def has_network_id(self, network_id):
        """Check if a network ID exists in any of the networks"""
        return any(info['network_id'] == network_id for info in self.networks.values())
    
    def get_url_by_network_id(self, network_id):
        for network, details in self.networks.items():
            if details['network_id'] == network_id:
                return details['url']
        return self.networks['optimism']['url']  # Default to Optimism if no match is found, script crashes if we dont return a default