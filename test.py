# main.py
import json
import ast
import sys
import argparse
import textwrap
from pathlib import Path
import colorsys
import hashlib

# --- Configuration for Visualization ---
MODULE_COLOR_MAP = {
    "api": "#d4e1f5",       # Light Blue
    "database": "#d5f5e3",  # Light Green
    "models": "#fff2cc",    # Light Yellow
    "utils": "#f5e1d4",     # Light Orange
}

# --- GraphEnhancer Class and other helpers remain the same ---
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
                # Store the source code lines in the cache
                self.file_cache[filepath] = {"tree": tree, "imports": import_map, "source_lines": source_code.splitlines()}
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

def get_color_for_module(module_name):
    if module_name in MODULE_COLOR_MAP:
        return MODULE_COLOR_MAP[module_name]
    hash_val = int(hashlib.md5(module_name.encode()).hexdigest(), 16)
    hue = (hash_val % 360) / 360.0
    rgb = colorsys.hls_to_rgb(hue, 0.9, 0.8)
    return '#%02x%02x%02x' % (int(rgb[0]*255), int(rgb[1]*255), int(rgb[2]*255))

# --- MODIFIED: The code preview logic is now more precise ---
def get_code_preview(filepath, start_line, end_line, file_cache, max_lines=20):
    try:
        source_lines = file_cache[filepath]['source_lines']
        
        # --- NEW LOGIC: Only grab lines within the function's bounds ---
        function_lines = source_lines[start_line - 1 : end_line]
        total_lines = len(function_lines)
        
        # --- NEW LOGIC: Decide if truncation is necessary ---
        if total_lines > max_lines:
            preview_lines = function_lines[:max_lines]
            remaining_lines = total_lines - max_lines
            suffix = f"\\l... ({remaining_lines} more lines)\\l"
        else:
            preview_lines = function_lines
            suffix = "\\l" # Add a final line break for padding

        # Dedent, escape for DOT, and format
        preview_text = textwrap.dedent("\n".join(preview_lines))
        escaped_text = preview_text.replace('"', '\\"').replace("\n", "\\l")
        
        return escaped_text + suffix
    except Exception:
        return "Could not load code preview."

# --- The rest of the script is unchanged ---
def save_as_dot_file(graph: dict, full_graph: dict, file_cache: dict, output_path: str):
    print(f"Generating DOT file with previews...", file=sys.stderr)
    dot_lines = ['digraph CallGraph {', '  rankdir="LR";', '  node [shape=box, style="rounded,filled", fontname="Helvetica"];', '  edge [fontname="Helvetica"];']
    all_nodes_in_subgraph = set(graph.keys()) | {callee for data in graph.values() for callee in data.get("callees", [])}
    for node_name in all_nodes_in_subgraph:
        node_data = full_graph.get(node_name)
        attributes = {}
        module_name = node_name.split('.')[1] if node_name.startswith('src.') else node_name.split('.')[0]
        attributes['fillcolor'] = f'"{get_color_for_module(module_name)}"'
        if node_data:
            filepath = node_data.get("filepath", "")
            start_line = node_data.get("lineno", 0)
            end_line = node_data.get("end_lineno", 0)
            tooltip = get_code_preview(filepath, start_line, end_line, file_cache)
            attributes['tooltip'] = f'"{tooltip}"'
        attr_string = ", ".join([f'{k}={v}' for k, v in attributes.items()])
        dot_lines.append(f'  "{node_name}" [{attr_string}];')
    for caller, data in graph.items():
        for callee in data.get("callees", []):
            dot_lines.append(f'  "{caller}" -> "{callee}";')
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
    parser.add_argument("target_function", nargs='?', help="Optional: The full name of the function to analyze (e.g., module.ClassName.method_name)")
    parser.add_argument("--dot", help="Optional: Specify a filename to save a visual graph (e.g., my_graph.dot)")
    parser.add_argument("--o", "--overview", action="store_true", help="Generate a DOT file of the entire project graph.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--f", "--forward", action="store_true", help="Show forward dependency tracking only.")
    group.add_argument("--b", "--backward", action="store_true", help="Show backward dependency tracking only.")
    group.add_argument("--full", action="store_true", help="Show both forward and backward tracking (default).")
    args = parser.parse_args()
    if not args.target_function and not args.o:
        parser.error("A target_function is required unless you are using the --o flag to generate a full project overview.")
    enhancer = GraphEnhancer("src/.nuanced/nuanced-graph.json")
    enhanced_graph = enhancer.enhance()
    if args.o and not args.target_function:
        if not args.dot:
            parser.error("The --o flag requires the --dot <filename> flag to be useful when no target_function is specified.")
        save_as_dot_file(enhanced_graph, enhanced_graph, enhancer.file_cache, args.dot)
        sys.exit(0)
    is_forward_only = args.f
    is_backward_only = args.b
    is_full_report = args.full or not (is_forward_only or is_backward_only)
    if args.dot:
        graph_for_dot_viz = {}
        if args.o:
            graph_for_dot_viz = enhanced_graph
        elif is_forward_only:
            forward_tree = get_deep_forward_trace(enhanced_graph, args.target_function)
            graph_for_dot_viz = {func: {"callees": callees} for func, callees in forward_tree.items()}
        elif is_backward_only:
            callers = get_backward_trace(enhanced_graph, args.target_function)
            graph_for_dot_viz = {caller: {"callees": [args.target_function]} for caller in callers}
        else:
            forward_tree = get_deep_forward_trace(enhanced_graph, args.target_function)
            callers = get_backward_trace(enhanced_graph, args.target_function)
            graph_for_dot_viz = {func: {"callees": callees} for func, callees in forward_tree.items()}
            for caller in callers:
                if caller not in graph_for_dot_viz:
                    graph_for_dot_viz[caller] = {"callees": []}
                if args.target_function not in graph_for_dot_viz[caller]["callees"]:
                    graph_for_dot_viz[caller]["callees"].append(args.target_function)
        save_as_dot_file(graph_for_dot_viz, enhanced_graph, enhancer.file_cache, args.dot)
    final_report = {"function": args.target_function, "filepath": enhanced_graph.get(args.target_function, {}).get("filepath")}
    if is_forward_only or is_full_report:
        final_report["forward_dependency_tree"] = get_deep_forward_trace(enhanced_graph, args.target_function)
    if is_backward_only or is_full_report:
        final_report["backward_tracking_callers"] = get_backward_trace(enhanced_graph, args.target_function)
    print(json.dumps(final_report, indent=2))