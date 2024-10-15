import base64
from time import strftime
from flask import Flask, json, request, jsonify, make_response, render_template, session
import jwt
from datetime import UTC, datetime, timedelta, timezone
import sqlite3

conn = sqlite3.connect('totally_not_my_privateKeys.db')
cursor = conn.cursor()
conn.execute('''CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)''')
conn.commit()

app = Flask(__name__)

secret_key = '3ba010226cd84939b9eed91aa6bd9519' # the secret key for encoding

secret_key_bytes = secret_key.encode('utf-8')

base64_encoded_key = base64.urlsafe_b64encode(secret_key_bytes).decode('utf-8') # this is the base64 encoded key for the jwks

jwks_data = {
        "keys": [
            {
                "kty":"oct",
                "alg":"HS256",
                "k":"3ba010226cd84939b9eed91aa6bd9519",
                "kid":"2"
            },
            {
                "kty":"oct",
                "k":base64_encoded_key,
                "alg":"HS256",
                "kid":"1",
                "use": "sig"
            }
        ]
}

#converts the expiration time to string
jwks_dict = json.loads(json.dumps(jwks_data))
key1 = next((key1 for key1 in jwks_dict['keys'] if key1['kid'] == "1"), None)
key2 = next((key2 for key2 in jwks_dict['keys'] if key2['kid'] == "2"), None)
jwk_json1 = json.dumps(key1)
jwk_json2 = json.dumps(key2)
jwk_bytes1 = jwk_json1.encode('utf-8')
jwk_bytes2 = jwk_json2.encode('utf-8')
early = datetime.now(UTC) - timedelta(seconds=10)
late = datetime.now(UTC) + timedelta(hours=1)
time1 = int(early.timestamp())
time2 = int(late.timestamp())

#insert the keys into database 
cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (jwk_bytes1, time2))
conn.commit()
cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (jwk_bytes2, time1))

conn.commit()
conn.close()

@app.route('/auth', methods=['POST'])
def auth():
    print(datetime.now(UTC) - timedelta(seconds=10))
    expired = request.args.get('expired') is not None # checks If the “expired” query parameter is present

    # payload data
    body = {
        'Fullname': "username",
        'Password': "password",
        'iat': datetime.now(UTC),
    }

    if expired:
        # makes the token already expired
        body['exp'] = datetime.now(UTC) - timedelta(seconds=10)  # Expired 10 seconds ago
        token = jwt.encode(body, '3ba010226cd84939b9eed91aa6bd9519', algorithm='HS256', headers={'kid': '3'}) # changes the kid if expired
    else:
        # Sets a future expiration time
        body['exp'] = datetime.now(UTC) + timedelta(hours=1)  # Expires in 1 hour
        token = jwt.encode(body, '3ba010226cd84939b9eed91aa6bd9519', algorithm='HS256', headers={'kid': '1'})

    return jsonify({"token": token})

@app.route('/.well-known/jwks.json', methods=['GET'])
def verify():
    
    return jsonify(jwks_data)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)