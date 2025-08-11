# main.py
import json
import ast
import sys
import argparse
from pathlib import Path

class GraphEnhancer:
    def __init__(self, graph_path):
        self.graph_path = Path(graph_path)
        if not self.graph_path.exists():
            print(f"Error: Graph file not found at {graph_path}", file=sys.stderr)
            sys.exit(1)
        self.graph = json.loads(self.graph_path.read_text())
        self.file_cache = {}
        self.root_package = ""
        if self.graph:
            first_key = next(iter(self.graph))
            if '.' in first_key:
                self.root_package = first_key.split('.')[0]

    def get_file_details(self, filepath):
        if filepath not in self.file_cache:
            try:
                source_code = Path(filepath).read_text()
                tree = ast.parse(source_code)
                import_map = {}
                for node in ast.walk(tree):
                    if isinstance(node, ast.ImportFrom) and node.module:
                        module_name = node.module.lstrip('.') if node.level > 0 else node.module
                        for alias in node.names:
                            import_map[alias.name] = module_name
                self.file_cache[filepath] = {"tree": tree, "imports": import_map}
            except Exception as e:
                print(f"Warning: Could not parse {filepath}. Error: {e}", file=sys.stderr)
                self.file_cache[filepath] = None
        return self.file_cache[filepath]

    class MethodCallVisitor(ast.NodeVisitor):
        def __init__(self, params_with_types, import_map, current_module_name, root_package):
            self.params = params_with_types
            self.import_map = import_map
            self.current_module_name = current_module_name
            self.root_package = root_package
            self.found_callees = []

        def visit_Call(self, node):
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                param_name = node.func.value.id
                if param_name in self.params:
                    method_name = node.func.attr
                    param_type_name = self.params[param_name]
                    module_name = self.import_map.get(param_type_name)
                    if not module_name:
                        module_name = self.current_module_name
                    full_callee_name = f"{self.root_package}.{module_name}.{param_type_name}.{method_name}"
                    self.found_callees.append(full_callee_name)
            self.generic_visit(node)

    def enhance(self):
        for function_name, data in self.graph.items():
            filepath = data.get("filepath")
            if not filepath: continue
            file_details = self.get_file_details(filepath)
            if not file_details: continue
            tree, import_map = file_details["tree"], file_details["imports"]
            current_module_name = Path(filepath).stem
            target_func_name = function_name.split('.')[-1]
            node_to_visit = None
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == target_func_name:
                    node_to_visit = node
                    break
            if node_to_visit:
                params_with_types = {arg.arg: ast.unparse(arg.annotation).strip() for arg in node_to_visit.args.args if arg.annotation}
                if not params_with_types: continue
                visitor = self.MethodCallVisitor(params_with_types, import_map, current_module_name, self.root_package)
                visitor.visit(node_to_visit)
                if visitor.found_callees:
                    for callee in visitor.found_callees:
                        if callee not in data["callees"]:
                            data["callees"].append(callee)
        return self.graph

def save_as_dot_file(graph: dict, output_path: str):
    print(f"Generating DOT file...", file=sys.stderr)
    dot_lines = ['digraph CallGraph {', '  rankdir="LR";', '  node [shape=box, style=rounded, fontname="Helvetica"];', '  edge [fontname="Helvetica"];']
    for caller, data in graph.items():
        if not data.get("callees"): continue
        sanitized_caller = f'"{caller}"'
        for callee in data.get("callees", []):
            sanitized_callee = f'"{callee}"'
            dot_lines.append(f"  {sanitized_caller} -> {sanitized_callee};")
    dot_lines.append('}')
    Path(output_path).write_text("\n".join(dot_lines))
    print(f"✅ DOT file saved to {output_path}", file=sys.stderr)

def get_deep_forward_trace(graph: dict, start_function: str) -> dict:
    dependency_tree = {}
    to_visit = [start_function]
    visited = set()
    while to_visit:
        current_function = to_visit.pop(0)
        if current_function in visited: continue
        visited.add(current_function)
        node_data = graph.get(current_function)
        if node_data:
            direct_callees = node_data.get("callees", [])
            dependency_tree[current_function] = direct_callees
            for callee in direct_callees:
                if callee not in visited:
                    to_visit.append(callee)
    return dependency_tree

def get_backward_trace(graph: dict, target_function: str) -> list:
    callers = []
    for function_name, data in graph.items():
        if target_function in data.get("callees", []):
            callers.append(function_name)
    return callers

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a dependency trace for a function.")
    parser.add_argument("target_function", help="The full name of the function to analyze (e.g., module.ClassName.method_name)")
    parser.add_argument("--dot", help="Optional: Specify a filename to save a visual graph (e.g., my_graph.dot)")
    
    # --- NEW: Added --o flag for overview ---
    parser.add_argument("--o", "--overview", action="store_true", help="Generate a DOT file of the entire project graph, overriding other flags for the DOT output.")
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--f", "--forward", action="store_true", help="Show forward dependency tracking only.")
    group.add_argument("--b", "--backward", action="store_true", help="Show backward dependency tracking only.")
    group.add_argument("--full", action="store_true", help="Show both forward and backward tracking (default).")
    args = parser.parse_args()
    
    is_forward_only = args.f
    is_backward_only = args.b
    is_full_report = args.full or not (is_forward_only or is_backward_only)
    
    enhancer = GraphEnhancer("src/.nuanced/nuanced-graph.json")
    enhanced_graph = enhancer.enhance()
    
    if args.dot:
        graph_for_dot = {}
        # --- NEW LOGIC: Prioritize the --o flag for the DOT file ---
        if args.o:
            graph_for_dot = enhanced_graph
        elif is_forward_only:
            forward_tree = get_deep_forward_trace(enhanced_graph, args.target_function)
            graph_for_dot = {func: {"callees": callees} for func, callees in forward_tree.items()}
        elif is_backward_only:
            callers = get_backward_trace(enhanced_graph, args.target_function)
            graph_for_dot = {caller: {"callees": [args.target_function]} for caller in callers}
        else: # is_full_report or default
            forward_tree = get_deep_forward_trace(enhanced_graph, args.target_function)
            callers = get_backward_trace(enhanced_graph, args.target_function)
            graph_for_dot = {func: {"callees": callees} for func, callees in forward_tree.items()}
            for caller in callers:
                if caller not in graph_for_dot:
                    graph_for_dot[caller] = {"callees": []}
                if args.target_function not in graph_for_dot[caller]["callees"]:
                    graph_for_dot[caller]["callees"].append(args.target_function)
        
        save_as_dot_file(graph_for_dot, args.dot)

    # JSON Report generation is unaffected by the --o flag
    final_report = {"function": args.target_function, "filepath": enhanced_graph.get(args.target_function, {}).get("filepath")}
    if is_forward_only or is_full_report:
        final_report["forward_dependency_tree"] = get_deep_forward_trace(enhanced_graph, args.target_function)
    if is_backward_only or is_full_report:
        final_report["backward_tracking_callers"] = get_backward_trace(enhanced_graph, args.target_function)
    print(json.dumps(final_report, indent=2))