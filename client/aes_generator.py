import base64, os
print(base64.b64encode(os.urandom(32)).decode())
