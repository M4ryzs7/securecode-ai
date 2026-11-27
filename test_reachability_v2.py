from reachability import analyze_reachability


def _one(code):
    results = analyze_reachability(code)
    assert len(results) == 1, results
    return results[0]


def test_basic_tainted_eval():
    code = '''
from flask import Flask, request
app = Flask(__name__)

@app.route("/calc")
def calc():
    expr = request.args.get("e")
    return str(eval(expr))
'''
    r = _one(code)
    assert r["source"]["name"] == "request.args.get"


def test_reassignment_to_safe_value_does_not_hide_taint_at_sink():
    code = '''
import os
from flask import Flask, request
app = Flask(__name__)

@app.route("/run")
def run_cmd():
    cmd = request.args.get("c")
    os.system(cmd)
    cmd = "safe"
    return "ok"
'''
    r = _one(code)
    assert r["source"] is not None


def test_safe_value_at_sink_is_not_tainted():
    code = '''
import os
from flask import Flask, request
app = Flask(__name__)

@app.route("/run")
def run_cmd():
    cmd = request.args.get("c")
    cmd = "safe"
    os.system(cmd)
    return "ok"
'''
    r = _one(code)
    assert r["source"] is None


def test_nested_call_and_string_concat():
    code = '''
import os
from flask import Flask, request
app = Flask(__name__)

@app.route("/x")
def x():
    name = request.form.get("n")
    os.system("ls " + name)
    return "ok"
'''
    r = _one(code)
    assert r["source"]["name"] == "request.form.get"


def test_blueprint_route_and_direct_source():
    code = '''
import subprocess
from flask import Blueprint, request
bp = Blueprint("b", __name__)

@bp.route("/p")
def p():
    subprocess.run(request.args["cmd"], shell=True)
    return "ok"
'''
    r = _one(code)
    assert r["source"]["name"] == "request.args[]"


def test_generic_run_method_is_not_a_sink():
    code = '''
from flask import Flask
app = Flask(__name__)

@app.route("/j")
def j():
    runner.run(task)
    return "ok"
'''
    assert analyze_reachability(code) == []


def test_sink_reached_through_helper_function():
    code = '''
from flask import Flask, request
app = Flask(__name__)

def helper(v):
    eval(v)

@app.route("/h")
def h():
    helper(request.args.get("v"))
    return "ok"
'''
    r = _one(code)
    assert r["sink"]["function"] == "helper"
    # taint through function parameters is a known limit
    assert r["source"] is None


def test_origin_variable_kept_through_assignment_chain():
    code = '''
from flask import Flask, request
app = Flask(__name__)

@app.route("/search")
def search():
    user_input = request.args.get("q")
    query = user_input
    eval(query)
    return "OK"
'''
    r = _one(code)
    assert r["source"]["variable"] == "user_input"
    assert r["source"]["line"] == 7
