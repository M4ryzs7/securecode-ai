from flask import Flask, request

app = Flask(__name__)

@app.route("/search")
def search():
    user_input = request.args.get("q")
    eval(user_input)
    return "Search completed"