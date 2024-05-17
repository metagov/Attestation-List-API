class SchemaIDs:
    def __init__(self):
        self.schemas = {
            "dao_registry_schema": '0x25eb07102ee3f4f86cd0b0c4393457965b742b8acc94aa3ddbf2bc3f62ed1381',
            "context_schema_id": '0xcc6c9b07bfccd15c8f313d23bf4389fb75629a620c5fa669c898bf1e023f2508'
        }

    def __getitem__(self, key):
        """Allows dictionary-like access"""
        return self.schemas.get(key, "Schema ID not found")
    
    