'''
It verifies a self-verified file
Usage:
> python3 verify_svf.py <input-file> <name>
> python3 verify_svf.py <input-file> <name> <output-file>
'''

import hashlib
import sys
import os
import json
from jwcrypto import jwk, jws
from didself import registry

def verify_svci(input, name):
    _input = input.split('\n',1)
    _header = _input[0]
    print(_header)
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
    if(not registry.verify(document,document_proof)):
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


def main():
    if (len(sys.argv) != 3 and len(sys.argv) != 4 ):
        print("Usage: verify_svf.py <input-file> <name>")
        print("Usage: verify_svf.py <input-file> <name> <output-file>")
        exit(os.EX_USAGE)

    with open(sys.argv[1], "r") as _file:
        input_file = _file.read()
    
    name = sys.argv[2]
    result = verify_svci(input_file, name)
    print(result)

if __name__ == "__main__":
    main()
    exit(os.EX_OK)