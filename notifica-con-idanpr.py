from jose import jwt
from jose.constants import Algorithms
import http.client, urllib.parse
import random
import hashlib
import base64
import requests
import json
import datetime
import uuid
import os

def clear():
  os.system('clear')

def get_private_key(key_path):
  with open(key_path, "rb") as private_key:
    return private_key.read()

def generate_jwt(payload, rsa_key, headers_rsa):
  return jwt.encode(payload, rsa_key, algorithm=Algorithms.RS256, headers=headers_rsa)

def create_audit_payload(clientid, audience, purposeid, userid, location, loa, dnonce, issued, expire_in):
  return {
    "userID": userid,
    "userLocation": location,
    "LoA": loa,
    "iss" : clientid,
    "aud" : audience,
    "purposeId": purposeid,
    "dnonce" : dnonce,
    "jti": str(uuid.uuid4()),
    "iat": issued,
    "nbf" : issued,
    "exp": expire_in
  }

def create_client_assertion_payload(clientid, purposeid, audit_hash, issued, expire_in):
  return {
    "iss": clientid,
    "sub": clientid,
    "aud": "auth.uat.interop.pagopa.it/client-assertion",
    "purposeId": purposeid,
    "jti": str(uuid.uuid4()),
    "iat": issued,
    "exp": expire_in,
    "digest": {
        "alg": "SHA256",
        "value": audit_hash
    }
  }

def request_voucher(clientid, client_assertion):
  params = urllib.parse.urlencode({
    'client_id': clientid,
    'client_assertion': client_assertion,
    'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    'grant_type': 'client_credentials'
  })
  headers = {"Content-type": "application/x-www-form-urlencoded"}
  conn = http.client.HTTPSConnection("auth.uat.interop.pagopa.it")
  conn.request("POST", "/token.oauth2", params, headers)
  response = conn.getresponse()
  return json.loads(response.read())["access_token"]

def create_signature_payload(clientid, audience, purposeid, digest, type, encoding, issued, expire_in):
  return {
    "iss" : clientid,
    "aud" : audience,
    "purposeId": purposeid,
    "sub": clientid,
    "jti": str(uuid.uuid4()),
    "iat": issued,
    "nbf" : issued,
    "exp": expire_in,
    "signed_headers": [
        {"digest": digest},
        {"content-type": type},
        {"content-encoding": encoding}
    ]
  }

def make_api_call(api_url, headers, body):
  response = requests.post(api_url, data=body.encode('UTF-8'), headers=headers, verify=False)
  return response.json()

if __name__ == '__main__':
  clientid = 'client-id-here' #found in PDND
  keyid = 'key-id-here' #found in PDND
  purposeid_C030 = 'purpose-id-here' #found in PDND
  purposeid_C001 = 'purpose-id-here' #found in PDND
  userid = 'admin'
  location = 'testP'
  loa = 'LoA2'
  audience_C030 = "https://modipa-val.anpr.interno.it/govway/rest/in/MinInternoPortaANPR/C030-servizioAccertamentoIdUnicoNazionale/v1"
  audience_C001 = "https://modipa-val.anpr.interno.it/govway/rest/in/MinInternoPortaANPR/C001-servizioNotifica/v1"
  target_C030 = "https://modipa-val.anpr.interno.it/govway/rest/in/MinInternoPortaANPR-PDND/C030-servizioAccertamentoIdUnicoNazionale/v1/anpr-service-e002"
  target_C001 = "https://modipa-val.anpr.interno.it/govway/rest/in/MinInternoPortaANPR-PDND/C001-servizioNotifica/v1/anpr-service-e002"
  
  # C030 Request
  request_C030 = '{"idOperazioneClient":"1","criteriRicerca":{"codiceFiscale":"QNTSGT90A01H501X"},"datiRichiesta":{"dataRiferimentoRichiesta":"2024-05-18","motivoRichiesta":"PROT.NUM.12345","casoUso":"C030"}}'
  
  rsaKey = get_private_key('eservice-client-keypair.rsa.priv path here')

  issued = datetime.datetime.utcnow()
  expire_in = issued + datetime.timedelta(minutes=43200)
  dnonce = random.randint(1000000000000, 9999999999999)

  headers_rsa = {
    "kid": keyid,
    "alg": 'RS256',
    "typ": 'JWT'
  }

  # C030 Request
  audit_payload = create_audit_payload(clientid, audience_C030, purposeid_C030, userid, location, loa, dnonce, issued, expire_in)
  audit = generate_jwt(audit_payload, rsaKey, headers_rsa)
  audit_hash = hashlib.sha256(audit.encode('UTF-8')).hexdigest()

  clear()
  print("audit C030 =", audit)
  print("audit C030 hash =", audit_hash)

  client_assertion_payload = create_client_assertion_payload(clientid, purposeid_C030, audit_hash, issued, expire_in)
  client_assertion = generate_jwt(client_assertion_payload, rsaKey, headers_rsa)
  print("client assertion C030 =", client_assertion)

  voucher = request_voucher(clientid, client_assertion)
  print("voucher C030 =", voucher)

  body_digest = hashlib.sha256(request_C030.encode('UTF-8'))
  digest = 'SHA-256=' + base64.b64encode(body_digest.digest()).decode('UTF-8')
  print("body_digest C030 =", body_digest)

  signature_payload = create_signature_payload(clientid, audience_C030, purposeid_C030, digest, 'application/json', 'UTF-8', issued, expire_in)
  signature = generate_jwt(signature_payload, rsaKey, headers_rsa)
  print("signature C030 =", signature)

  headers = {
    "Accept":"application/json",
    "Content-Type":'application/json',
    "Content-Encoding":'UTF-8',
    "Digest":digest,
    "Authorization":"Bearer " + voucher,
    "Agid-JWT-TrackingEvidence":audit,
    "Agid-JWT-Signature":signature
  }

  print("headers C030 =", headers)

  response = make_api_call(target_C030, headers, request_C030)
  print("response C030 =", response)
  idANPR = response['listaSoggetti']['datiSoggetto'][0]['identificativi']['idANPR']


  # C001 Request
  request_C001 = f'{{"idOperazioneClient":"1","criteriRicerca":{{"idANPR":"{idANPR}"}}, "datiRichiesta":{{"dataRiferimentoRichiesta":"2024-05-18","motivoRichiesta":"PROT.NUM.12345","casoUso":"C001"}}}}'
  
  audit_payload = create_audit_payload(clientid, audience_C001, purposeid_C001, userid, location, loa, dnonce, issued, expire_in)
  audit = generate_jwt(audit_payload, rsaKey, headers_rsa)
  audit_hash = hashlib.sha256(audit.encode('UTF-8')).hexdigest()
  print("audit C001 =", audit)
  print("audit C001 hash =", audit_hash)

  client_assertion_payload = create_client_assertion_payload(clientid, purposeid_C001, audit_hash, issued, expire_in)
  client_assertion = generate_jwt(client_assertion_payload, rsaKey, headers_rsa)
  print("client C001 assertion =", client_assertion)

  voucher = request_voucher(clientid, client_assertion)
  print("voucher C001 =", voucher)

  body_digest = hashlib.sha256(request_C001.encode('UTF-8'))
  digest = 'SHA-256=' + base64.b64encode(body_digest.digest()).decode('UTF-8')
  print("body_digest C001 =", body_digest)

  signature_payload = create_signature_payload(clientid, audience_C001, purposeid_C001, digest, 'application/json', 'UTF-8', issued, expire_in)
  signature = generate_jwt(signature_payload, rsaKey, headers_rsa)
  print("signature C001 =", signature)

  headers = {
    "Accept":"application/json",
    "Content-Type":'application/json',
    "Content-Encoding":'UTF-8',
    "Digest":digest,
    "Authorization":"Bearer " + voucher,
    "Agid-JWT-TrackingEvidence":audit,
    "Agid-JWT-Signature":signature
  }

  print("headers C001 =", headers)

  response = make_api_call(target_C001, headers, request_C001)
  print("response C001 =", response)
