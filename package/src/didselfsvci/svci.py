import hashlib
import sys
import json
from jwcrypto import jwk, jws
from didself import registry


def generate_svci_header(input, jwk_key, did):
    sha256 = hashlib.sha256() 
    sha256.update(input.encode())
    metadata = {
        'name': did.split(":")[2],
        'sha-256':sha256.hexdigest()
    }
    key = jwk.JWK(**jwk_key)
    jws_payload = json.dumps(metadata)
    proof = jws.JWS(jws_payload.encode('utf-8'))
    proof.add_signature(key, None, json.dumps({"alg": "EdDSA"}),None)  
    return metadata, proof.serialize(compact=True) 

def verify_svci(input, name):
    _input = input.split('\n',1)
    _header = _input[0]
    data = _input[1]
    header = json.loads(_header)
    document = header[0]
    document_proof = header[1]
    ser_proof = header[2]
    proof = jws.JWS()
    proof.deserialize(ser_proof)
    payload = json.loads(proof.objects['payload'].decode())
    ###----Check if file name is included in the metadata and in the did document---
    if(payload['name'] != name):
        return False
    if(document['id'].split(":")[2] != name):
        return False
    ###---Check the DID document
    owner_registry = registry.DIDSelfRegistry(jwk.JWK.generate(kty='EC', crv='P-256'))
    try:
        owner_registry.load(document,document_proof)
    except:
        print("Cannot validate DID document")
        return False
     ###---Check the metadata hash---
    sha256 = hashlib.sha256() 
    sha256.update(data.encode())
    if(payload['sha-256'] != sha256.hexdigest()):
        return False
    return True
    ###---Check the signature of the metadata---
    key_dict = document['assertion'][0]['publicKeyJwk']
    key = jwk.JWK(**key_dict)
    try:
        proof.verify(key)
    except:
        return False
