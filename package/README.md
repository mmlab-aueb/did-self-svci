# Self-Verifiable Content Items
Self-Verifiable Content Items using [did:self](https://github.com/mmlab-aueb/did-self)

# SVCI generation
```python
# DID creation
# Generate DID and initial secret key
did_key = jwk.JWK.generate(kty='OKP', crv='Ed25519')
# Initialize registry
registry = registry.DIDSelfRegistry(did_key)
# Generate the DID document
did_key_dict = did_key.export(as_dict=True)
did = "did:self:" + did_key_dict['x']
did_document = {
        'id': did,
        'assertion': [{
            'id': did + '#key1',
            'type': "JsonWebKey2020",
            'publicKeyJwk': did_key_dict
        }],  
    }
registry.create(did_document)
document, document_proof,_ = registry.read()
file_data = "hello word"
metadata, metadata_proof= svci.generate_svci_header(file_data, did_key_dict, did)
file_header = []
file_header.append(document)
file_header.append(document_proof)
file_header.append(metadata_proof)
file = json.dumps(file_header) + "\n" + file_data
print(file)
```

# SVCI verification
```python
result = svci.verify_svci(file, did.split(":")[2])
print(result)
```

