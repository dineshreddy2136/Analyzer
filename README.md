# Python Code Dependency Analyzer

A sophisticated command-line tool for analyzing Python codebases and generating detailed dependency reports and visualizations. Built on top of the `nuanced` static analysis tool with significant enhancements for complex call pattern detection.

## Features

### 🔍 **Deep Call Analysis**
- **Nested Function Discovery**: Finds functions within functions that static analysis often misses
- **Method Chain Resolution**: Traces complex calls like `df['column'].apply(func)`
- **Callback Detection**: Identifies function references passed as arguments
- **Type-Aware Calls**: Uses variable type inference to resolve method calls

### 🎨 **Rich Visualizations**
- **Interactive DOT Graphs**: Generate Graphviz-compatible visualizations
- **Code Preview Tooltips**: Hover over nodes to see actual source code
- **Level-Based Coloring**: Visual depth indication in dependency traces
- **Module-Based Coloring**: Color coding by module/package

### ⚡ **Performance Optimizations**
- **O(1) Function Lookups**: Pre-computed hash maps for fast reference resolution
- **Efficient Queue Operations**: Using `collections.deque` for optimal traversal
- **Smart Caching**: File parsing results cached for repeated analysis

### 🎯 **Domain-Specific Support**
- **AWS Glue/PySpark**: Enhanced detection of Glue transforms and Spark operations
- **Pandas Operations**: Improved tracing of DataFrame method calls
- **Type Inference**: Configurable type inference for framework-specific patterns

## Installation

```bash
# Install base dependencies
pip install nuanced

# For visualization (optional but recommended)
brew install graphviz  # macOS
# or
apt-get install graphviz  # Ubuntu/Debian
```

## Usage

### Basic Analysis

```bash
# Analyze a specific function
python3 main.py --func src.module.my_function --f

# Analyze an entire script
python3 main.py --file src/main.py --full

# Generate visual graph
python3 main.py --func src.main --f --dot output.dot
```

### Advanced Options

```bash
# Limit recursion depth (useful for large codebases)
python3 main.py --func src.main --f --max-depth 3

# Generate overview of entire project
python3 main.py --o --dot project_overview.dot

# Backward dependency tracking
python3 main.py --func src.util.helper --b
```

### Report Types

- `--f/--forward`: Shows what functions the target calls (forward dependencies)
- `--b/--backward`: Shows what functions call the target (backward dependencies)  
- `--full`: Shows both forward and backward dependencies (default)

## Output Formats

### JSON Report (stdout)
```json
{
  "start_point": "src.main.process_data",
  "forward_dependency_tree": {
    "src.main.process_data": [
      "src.utils.validate_input",
      "src.transformers.clean_data",
      "src.main.save_results"
    ]
  }
}
```

### DOT Visualization
Generates Graphviz DOT files that can be rendered as:
```bash
# Generate SVG with interactive tooltips
dot -Tsvg output.dot -o output.svg

# Generate PNG 
dot -Tpng output.dot -o output.png
```

## Configuration

The tool supports configurable type inference through `TYPE_INFERENCE_MAP`:

```python
TYPE_INFERENCE_MAP = {
    'spark_session': 'SparkSession',
    'create_dynamic_frame': 'DynamicFrame',
    'toDF': 'DataFrame',
    'toPandas': 'pandas.DataFrame'
}
```

## Limitations

- **Dynamic Calls**: Cannot trace calls made through `getattr()`, `eval()`, etc.
- **Import Aliases**: Limited support for complex import aliasing
- **Decorators**: Does not analyze decorator effects on function calls
- **Type Hints**: Basic support for function parameter annotations only

## Examples

### AWS Glue ETL Analysis
```bash
# Analyze a Glue job's main function
python3 main.py --func src.glue_job.main --full --dot glue_deps.dot
```

This will trace:
- AWS Glue transform calls (`SplitRows.apply`, `ApplyMapping.apply`)
- DynamicFrame method calls
- Spark DataFrame operations
- Nested callback functions

### Data Pipeline Visualization
```bash
# Create overview of data processing pipeline
python3 main.py --file src/pipeline.py --forward --max-depth 4 --dot pipeline.dot
dot -Tsvg pipeline.dot -o pipeline.svg
```

## Contributing

The tool is designed for extensibility:

1. **Type Inference**: Add patterns to `TYPE_INFERENCE_MAP`
2. **Color Schemes**: Modify `MODULE_COLOR_MAP` for custom visualization
3. **AST Visitors**: Extend `MethodCallVisitor` for new call patterns

## Performance Tips

- Use `--max-depth` for very large codebases
- Enable caching by running multiple analyses on the same codebase
- Use `--forward` only when you don't need backward traces

## Troubleshooting

**"Start node not found"**: The tool will suggest similar functions and show available prefixes to help identify the correct function name.

**Empty results**: Ensure the `nuanced` tool has generated a graph file at `src/.nuanced/nuanced-graph.json`.

**Performance issues**: Try using `--max-depth` to limit analysis scope.
