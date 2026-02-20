# Contributing to mcpsec

Thank you for your interest in making MCP servers more secure! We welcome contributions of all kinds: new scanners, bug fixes, documentation improvements, and more.

## Development Setup

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/manthanghasadiya/mcpsec.git
    cd mcpsec
    ```

2.  **Create a virtual environment**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies**:
    ```bash
    pip install -e ".[dev]"
    ```

4.  **Run tests**:
    ```bash
    pytest
    ```

## Adding a New Scanner

`mcpsec` is designed to be extensible. To add a new scanner:

1.  Create a new file in `mcpsec/scanners/` (e.g., `my_new_scanner.py`).
2.  Inherit from `BaseScanner` and implement the `scan` method.

```python
from mcpsec.scanners.base import BaseScanner
from mcpsec.models import Finding, Severity

class MyNewScanner(BaseScanner):
    async def scan(self):
        # Your logic here
        # self.client.call_tool(...)
        
        # Report findings
        self.add_finding(Finding(
            severity=Severity.HIGH,
            title="My New Vulnerability",
            description="Found something bad..."
        ))
```

3.  Register your scanner in `mcpsec/engine.py` in the `_load_default_scanners` method (or equivalent registry mechanism).

## Reporting Bugs

Please use the GitHub Issues tab to report bugs or suggest features. Include as much detail as possible, including:
- Steps to reproduce
- Expected behavior
- Actual behavior
- `mcpsec` version

## Code Style

We use `ruff` and `mypy` for linting and formatting. Please run them before submitting a PR:

```bash
ruff check .
mypy .
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
