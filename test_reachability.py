from reachability import (
    discover_flask_routes,
    build_call_graph,
    find_reachable_functions,
    find_dangerous_sinks,
    analyze_reachability,
    find_user_input_sources,
)

def test_detects_flask_route():
    source = '''
from flask import Flask

app = Flask(__name__)

@app.route("/search")
def search():
    return "Hello"
'''

    routes = discover_flask_routes(source)

    assert len(routes) == 1
    assert routes[0]["path"] == "/search"
    assert routes[0]["function"] == "search"

def test_detects_multiple_flask_routes():
    source = '''
from flask import Flask

app = Flask(__name__)

@app.route("/search")
def search():
    return "Search"

@app.route("/login", methods=["POST"])
def login():
    return "Login"
'''

    routes = discover_flask_routes(source)

    assert len(routes) == 2
    assert routes[0]["path"] == "/search"
    assert routes[1]["path"] == "/login"

def test_detects_function_calls():
    source = '''
from flask import Flask

app = Flask(__name__)

def get_data():
    return "data"

@app.route("/search")
def search():
    result = get_data()
    return result
'''

    routes = discover_flask_routes(source)
    assert routes[0]["function"] == "search"

def test_builds_function_call_graph():
    source = '''
def process_data():
    return "processed"

def get_data():
    return process_data()

def search():
    return get_data()
'''

    graph = build_call_graph(source)

    assert "get_data" in graph["search"]
    assert "process_data" in graph["get_data"]

def test_finds_reachable_functions():
    graph = {
        "search": {"get_data"},
        "get_data": {"process_data"},
        "process_data": set(),
    }

    reachable = find_reachable_functions("search", graph)

    assert reachable == {"get_data", "process_data"}

def test_handles_recursive_function_calls():
    graph = {
        "search": {"get_data"},
        "get_data": {"process_data"},
        "process_data": {"get_data"},
    }

    reachable = find_reachable_functions("search", graph)

    assert reachable == {"get_data", "process_data"}

def test_detects_dangerous_sinks():
    source = '''
def search():
    eval("1 + 1")
    os.system("ls")
'''

    sinks = find_dangerous_sinks(source)

    sink_names = {sink["name"] for sink in sinks}

    assert "eval" in sink_names
    assert "os.system" in sink_names

def test_sink_contains_function_and_line():
    source = '''
def search():
    user_input = "test"
    eval(user_input)
'''

    sinks = find_dangerous_sinks(source)

    assert len(sinks) == 1
    assert sinks[0]["name"] == "eval"
    assert sinks[0]["function"] == "search"
    assert sinks[0]["line"] == 4

def test_finds_route_reachable_sinks():
    source = '''
from flask import Flask

app = Flask(__name__)

def execute_query():
    eval("1 + 1")

@app.route("/search")
def search():
    execute_query()
    return "OK"
'''

    routes = discover_flask_routes(source)
    graph = build_call_graph(source)
    sinks = find_dangerous_sinks(source)

    reachable = find_reachable_functions(
        routes[0]["function"],
        graph
    )

    assert "execute_query" in reachable
    assert any(
        sink["function"] == "execute_query"
        for sink in sinks
    )

def test_analyze_reachability_returns_route_and_sink():
    source = '''
from flask import Flask

app = Flask(__name__)

def execute_query():
    eval("1 + 1")

@app.route("/search")
def search():
    execute_query()
    return "OK"
'''

    results = analyze_reachability(source)

    assert len(results) == 1
    assert results[0]["route"] == "/search"
    assert results[0]["entry_function"] == "search"
    assert results[0]["sink"]["name"] == "eval"
    assert results[0]["sink"]["function"] == "execute_query"

def test_detects_user_input_reaching_eval():
    source = '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/search")
def search():
    user_input = request.args.get("q")
    eval(user_input)
    return "OK"
'''

    results = analyze_reachability(source)

    assert len(results) == 1
    assert results[0]["sink"]["name"] == "eval"
    assert results[0]["sink"]["function"] == "search"
    assert results[0]["source"] is not None

def test_detects_flask_request_source():
    source = '''
from flask import request

def search():
    user_input = request.args.get("q")
'''

    sources = find_user_input_sources(source)

    assert len(sources) == 1
    assert sources[0]["name"] == "request.args.get"
    assert sources[0]["variable"] == "user_input"
    assert sources[0]["function"] == "search"

def test_detects_source_through_variable_assignment():
    source = '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/search")
def search():
    user_input = request.args.get("q")
    query = user_input
    eval(query)
    return "OK"
'''

    results = analyze_reachability(source)

    assert len(results) == 1
    assert results[0]["source"] is not None
    assert results[0]["source"]["variable"] == "user_input"