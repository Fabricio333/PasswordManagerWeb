from flask import Flask, render_template, request, jsonify
from password_manager.seed import verify_seed_phrase, derive_keys
from password_manager.password import generate_password

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.post("/verify-seed")
def verify_seed():
    phrase = request.json.get("seedPhrase", "")
    if verify_seed_phrase(phrase):
        keys = derive_keys(phrase)
        return jsonify({"nsec": keys["nsec"], "npub": keys["npub"]})
    return jsonify({"error": "invalid seed phrase"}), 400

@app.post("/generate-password")
def gen_password():
    data = request.json
    pwd = generate_password(
        data["privateKey"], data["username"], data["site"], data["nonce"]
    )
    return jsonify({"password": pwd})

if __name__ == "__main__":
    app.run(debug=True)
