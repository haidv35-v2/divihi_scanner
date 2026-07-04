from flask import Flask, request
app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host")
    import os
    return os.popen("ping -c1 " + host).read()

SAFE = "example_placeholder_not_a_real_key"
