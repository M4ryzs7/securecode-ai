import ast


def discover_flask_routes(source: str) -> list[dict]:
    """
    Discover Flask routes using AST without executing the source code.
    """
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

            if decorator.func.attr not in {"route", "get", "post", "put", "delete", "patch"}:
                continue

            if not isinstance(decorator.func.value, ast.Name):
                continue

            if decorator.func.value.id != "app":
                continue

            path = None

            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                path = decorator.args[0].value

            if path is None:
                continue

            routes.append({
                "path": path,
                "function": node.name,
                "line": node.lineno,
            })

    return routes

def build_call_graph(source: str) -> dict:
    """
    Build a function call graph using AST.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}

    graph = {}

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_name = node.name
            graph[function_name] = set()

            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    if isinstance(child.func, ast.Name):
                        graph[function_name].add(child.func.id)

    return graph

def find_reachable_functions(entry_function: str, graph: dict) -> set:
    """
    Find all functions reachable from a given entry function.
    """
    visited = set()
    stack = [entry_function]

    while stack:
        current = stack.pop()

        if current in visited:
            continue

        visited.add(current)

        for called_function in graph.get(current, set()):
            if called_function not in visited:
                stack.append(called_function)

    visited.discard(entry_function)
    return visited

class SinkVisitor(ast.NodeVisitor):
    def __init__(self):
        self.sinks = []
        self.current_function = None

    def visit_FunctionDef(self, node):
        previous_function = self.current_function
        self.current_function = node.name

        self.generic_visit(node)

        self.current_function = previous_function

    def visit_AsyncFunctionDef(self, node):
        previous_function = self.current_function
        self.current_function = node.name

        self.generic_visit(node)

        self.current_function = previous_function

    def visit_Call(self, node):
        dangerous_functions = {"eval", "exec"}
        dangerous_methods = {"system", "popen", "run", "Popen"}

        func = node.func
        sink_name = None

        if isinstance(func, ast.Name):
            if func.id in dangerous_functions:
                sink_name = func.id

        elif isinstance(func, ast.Attribute):
            if func.attr in dangerous_methods:
                if isinstance(func.value, ast.Name):
                    sink_name = f"{func.value.id}.{func.attr}"

        if sink_name:
            self.sinks.append({
                "name": sink_name,
                "function": self.current_function,
                "line": node.lineno,
            })

        self.generic_visit(node)

class SourceVisitor(ast.NodeVisitor):
    def __init__(self):
        self.sources = []
        self.tainted_variables = {}
        self.current_function = None

    def visit_FunctionDef(self, node):
        previous = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = previous

    def visit_AsyncFunctionDef(self, node):
        previous = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = previous

    def visit_Assign(self, node):
        value = node.value
        source = None

        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "get"
            and isinstance(value.func.value, ast.Attribute)
            and value.func.value.attr == "args"
            and isinstance(value.func.value.value, ast.Name)
            and value.func.value.value.id == "request"
        ):
            source = {
                "name": "request.args.get",
                "variable": None,
                "function": self.current_function,
                "line": node.lineno,
            }

        elif isinstance(value, ast.Name):
            source = self.tainted_variables.get(
                (self.current_function, value.id)
            )

        for target in node.targets:
            if isinstance(target, ast.Name):
                key = (self.current_function, target.id)

                if source:
                    if source["variable"] is None:
                        source["variable"] = target.id
                        source["line"] = node.lineno

                    self.sources.append(source.copy())

                    self.tainted_variables[key] = source
                else:
                    self.tainted_variables.pop(key, None)

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
    """
    Connect Flask routes, function calls, sources and sinks.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    routes = discover_flask_routes(source)
    graph = build_call_graph(source)
    sinks = find_dangerous_sinks(source)
    source_visitor = SourceVisitor()
    source_visitor.visit(tree)

    tainted_variables = source_visitor.tainted_variables

    results = []

    sink_calls = {}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        sink_calls[node.lineno] = {
            arg.id
            for arg in node.args
            if isinstance(arg, ast.Name)
        }

    for route in routes:
        entry_function = route["function"]

        reachable = find_reachable_functions(
            entry_function,
            graph
        )

        reachable.add(entry_function)

        for sink in sinks:
            if sink["function"] not in reachable:
                continue

            matching_sources = [
            tainted_variables.get((sink["function"], arg))
            for arg in sink_calls.get(sink["line"], set())
            if tainted_variables.get((sink["function"], arg)) is not None
        ]

            results.append({
                "route": route["path"],
                "entry_function": entry_function,
                "sink": sink,
                "source": (
                    matching_sources[0]
                    if matching_sources else None
                ),
            })

    return results