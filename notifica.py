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
    encoded_string = private_key.read()
    return encoded_string

if __name__ == '__main__':

  clientid = 'client-id-here' #found in PDND
  keyid = 'key-id-here' #found in PDND
  purposeid = 'purpose-id-here' #found in PDND
  userid = 'username-here' #mario rossi
  location = 'device-id-here' #pc-123456
  loa = 'level of assurance' #LoA2 / SPID
  audience = 'https://modipa-val.anpr.interno.it/govway/rest/in/MinInternoPortaANPR/C001-servizioNotifica/v1'
  target = "https://modipa-val.anpr.interno.it/govway/rest/in/MinInternoPortaANPR-PDND/C001-servizioNotifica/v1/anpr-service-e002"
  request = '{"idOperazioneClient":"22","criteriRicerca":{"codiceFiscale":"DPLPRM90R10H501I"},"datiRichiesta":{"dataRiferimentoRichiesta":"2023-08-22","motivoRichiesta":"PROT.NUM.12345","casoUso":"C001"}}'

  issued = datetime.datetime.utcnow()
  delta = datetime.timedelta(minutes=43200)
  expire_in = issued + delta
  dnonce = random.randint(1000000000000, 9999999999999)

  rsaKey = get_private_key('eservice-client-keypair.rsa.priv path here')

  headers_rsa = {
    "kid": keyid,
    "alg": 'RS256',
    "typ": 'JWT'
  }

#crea assertion di audit
  jti = uuid.uuid4()
  audit_payload = {
    "userID": userid,
    "userLocation": location,
    "LoA": loa,
    "iss" : clientid,
    "aud" : audience,
    "purposeId": purposeid,
    "dnonce" : dnonce,
    "jti":str(jti),
    "iat": issued,
    "nbf" : issued,
    "exp": expire_in
  }

  audit = jwt.encode(audit_payload, rsaKey, algorithm=Algorithms.RS256, headers=headers_rsa)
  audit_hash = hashlib.sha256(audit.encode('UTF-8')).hexdigest()

  clear()
  print("audit =", audit)
  print("audit hash =", audit_hash)

#crea client assertion per richiesta voucher
  jti = uuid.uuid4()
  payload = {
    "iss": clientid,
    "sub": clientid,
    "aud": "auth.uat.interop.pagopa.it/client-assertion",
    "purposeId": purposeid,
    "jti": str(jti),
    "iat": issued,
    "exp": expire_in,
    "digest": {
        "alg": "SHA256",
        "value": audit_hash
    }
  }

  client_assertion = jwt.encode(payload, rsaKey, algorithm=Algorithms.RS256, headers=headers_rsa)
  print("client assertion =", client_assertion)

#effettua richiesta voucher
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

  voucher = json.loads(response.read())["access_token"]
  print("voucher=", voucher)

#prepara il body per la richiesta e relativo digest
  body = request
  type = 'application/json'
  encoding = 'UTF-8'
  body_digest = hashlib.sha256(body.encode('UTF-8'))
  digest = 'SHA-256=' + base64.b64encode(body_digest.digest()).decode('UTF-8')
  
  print("body_digest =", body_digest)

#crea signature
  jti = uuid.uuid4()
  payload = {
    "iss" : clientid,
    "aud" : audience,
    "purposeId": purposeid,
    "sub": clientid,
    "jti": str(jti),
    "iat": issued,
    "nbf" : issued,
    "exp": expire_in,
    "signed_headers": [
        {"digest": digest},
        {"content-type": type},
        {"content-encoding": encoding}
    ]
  }

  signature = jwt.encode(payload, rsaKey, algorithm=Algorithms.RS256, headers=headers_rsa)
  print("signature =", signature)

#effettua chiamata
  api_url = target
  headers =  {"Accept":"application/json",
    "Content-Type":type,
    "Content-Encoding":encoding,
    "Digest":digest,
    "Authorization":"Bearer " + voucher,
    "Agid-JWT-TrackingEvidence":audit,
    "Agid-JWT-Signature":signature
    }

  print("headers =", headers)

  response = requests.post(api_url, data=body.encode('UTF-8'), headers=headers, verify=False)
#  response = requests.get(api_url, headers=headers, verify=False)

  print("response =", response.json())


