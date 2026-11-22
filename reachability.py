"""
reachability.py - Lightweight Flask reachability analysis (AST only, nothing is executed).

This is NOT a full taint engine. Known limits:
  * analysis is per file (no cross-file calls)
  * taint is tracked through simple assignments, +=, f-strings, concatenation
  * taint is NOT tracked through function parameters / return values
  * only `import os` / `import subprocess` style sink calls are recognised
"""

import ast

ROUTE_METHODS = {"route", "get", "post", "put", "delete", "patch"}
REQUEST_CONTAINERS = {"args", "form", "values", "headers", "cookies"}
REQUEST_ATTRS = {"json", "data"}
DANGEROUS_NAMES = {"eval", "exec"}
DANGEROUS_CALLS = {
    ("os", "system"), ("os", "popen"),
    ("subprocess", "run"), ("subprocess", "Popen"),
    ("subprocess", "call"), ("subprocess", "check_output"),
    ("subprocess", "check_call"),
}


def _is_request(node) -> bool:
    return isinstance(node, ast.Name) and node.id == "request"


def direct_source_name(node):
    """Return the name of a user-input source if `node` itself is one, else None."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        func = node.func
        if (
            func.attr == "get"
            and isinstance(func.value, ast.Attribute)
            and _is_request(func.value.value)
            and func.value.attr in REQUEST_CONTAINERS
        ):
            return f"request.{func.value.attr}.get"
        if func.attr == "get_json" and _is_request(func.value):
            return "request.get_json"

    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Attribute)
        and _is_request(node.value.value)
        and node.value.attr in REQUEST_CONTAINERS
    ):
        return f"request.{node.value.attr}[]"

    if (
        isinstance(node, ast.Attribute)
        and _is_request(node.value)
        and node.attr in REQUEST_ATTRS
    ):
        return f"request.{node.attr}"

    return None


def _names_in(nodes) -> set:
    return {
        child.id
        for node in nodes
        for child in ast.walk(node)
        if isinstance(child, ast.Name)
    }


def taint_at(history: dict, function, variable: str, line: int):
    """Taint state of `variable` just BEFORE `line` (last assignment wins)."""
    state = None
    for assigned_line, entry in history.get((function, variable), []):
        if assigned_line < line:
            state = entry
    return state


def discover_flask_routes(source: str) -> list[dict]:
    """Discover Flask routes (app.route, bp.route, app.get, ...) without executing code."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    routes = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            if not isinstance(decorator.func, ast.Attribute):
                continue
            if decorator.func.attr not in ROUTE_METHODS:
                continue
            if not isinstance(decorator.func.value, ast.Name):
                continue

            path = None
            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                path = decorator.args[0].value
            if path is None:
                continue

            routes.append({"path": path, "function": node.name, "line": node.lineno})

    return routes


def build_call_graph(source: str) -> dict:
    """Function call graph using AST."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}

    graph = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            graph[node.name] = set()
            for child in ast.walk(node):
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                    graph[node.name].add(child.func.id)
    return graph


def find_reachable_functions(entry_function: str, graph: dict) -> set:
    """All functions reachable from the entry function (entry itself excluded)."""
    visited = set()
    stack = [entry_function]

    while stack:
        current = stack.pop()
        if current in visited:
            continue
        visited.add(current)
        for called in graph.get(current, set()):
            if called not in visited:
                stack.append(called)

    visited.discard(entry_function)
    return visited


class SinkVisitor(ast.NodeVisitor):
    def __init__(self):
        self.sinks = []
        self.current_function = None

    def _visit_function(self, node):
        previous = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = previous

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_Call(self, node):
        func = node.func
        sink_name = None

        if isinstance(func, ast.Name) and func.id in DANGEROUS_NAMES:
            sink_name = func.id
        elif (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and (func.value.id, func.attr) in DANGEROUS_CALLS
        ):
            sink_name = f"{func.value.id}.{func.attr}"

        if sink_name:
            args = list(node.args) + [k.value for k in node.keywords]

            direct = None
            for arg in args:
                for child in ast.walk(arg):
                    direct = direct_source_name(child)
                    if direct:
                        break
                if direct:
                    break

            self.sinks.append({
                "name": sink_name,
                "function": self.current_function,
                "line": node.lineno,
                "arg_names": sorted(_names_in(args)),
                "direct_source": direct,
            })

        self.generic_visit(node)


class SourceVisitor(ast.NodeVisitor):
    """Tracks which variables hold user input, line by line."""

    def __init__(self):
        self.sources = []
        self.history = {}          # (function, variable) -> [(line, entry_or_None), ...]
        self.current_function = None

    def _visit_function(self, node):
        previous = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = previous

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def _expr_source(self, expr, line):
        for child in ast.walk(expr):
            name = direct_source_name(child)
            if name:
                return {"name": name, "variable": None, "line": None}
            if isinstance(child, ast.Name):
                prior = taint_at(self.history, self.current_function, child.id, line)
                if prior:
                    # keep the ORIGIN of the taint (first variable and line)
                    return {
                        "name": prior["name"],
                        "variable": prior["variable"],
                        "line": prior["line"],
                    }
        return None

    def _record(self, target_name, source, line):
        entry = None
        if source:
            entry = {
                "name": source["name"],
                "variable": source.get("variable") or target_name,
                "function": self.current_function,
                "line": source.get("line") or line,
            }
            self.sources.append(entry.copy())
        self.history.setdefault((self.current_function, target_name), []).append((line, entry))

    def visit_Assign(self, node):
        source = self._expr_source(node.value, node.lineno)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._record(target.id, source, node.lineno)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        if isinstance(node.target, ast.Name):
            source = self._expr_source(node.value, node.lineno) or taint_at(
                self.history, self.current_function, node.target.id, node.lineno
            )
            self._record(node.target.id, source, node.lineno)
        self.generic_visit(node)


def find_user_input_sources(source: str) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    visitor = SourceVisitor()
    visitor.visit(tree)
    return visitor.sources


def find_dangerous_sinks(source: str) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    visitor = SinkVisitor()
    visitor.visit(tree)
    return visitor.sinks


def analyze_reachability(source: str) -> list[dict]:
    """Connect Flask routes, call graph, sinks and tainted sources."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    routes = discover_flask_routes(source)
    graph = build_call_graph(source)
    sinks = find_dangerous_sinks(source)

    source_visitor = SourceVisitor()
    source_visitor.visit(tree)

    results = []
    for route in routes:
        entry_function = route["function"]
        reachable = find_reachable_functions(entry_function, graph)
        reachable.add(entry_function)

        for sink in sinks:
            if sink["function"] not in reachable:
                continue

            matched = None
            for variable in sink["arg_names"]:
                state = taint_at(
                    source_visitor.history, sink["function"], variable, sink["line"]
                )
                if state:
                    matched = state
                    break

            if matched is None and sink.get("direct_source"):
                matched = {
                    "name": sink["direct_source"],
                    "variable": None,
                    "function": sink["function"],
                    "line": sink["line"],
                }

            results.append({
                "route": route["path"],
                "entry_function": entry_function,
                "sink": sink,
                "source": matched,
            })

    return results
