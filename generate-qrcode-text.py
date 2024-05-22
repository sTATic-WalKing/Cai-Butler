import json

res = {}
with open('rsa_pk.pem', 'rb') as f:
    res['pk'] = f.read().decode('utf8')
res['host'] = 'http://192.168.154.176:11151'
with open('qrcode_text', 'wb') as f:
    f.write(json.dumps(res).encode('utf8'))
