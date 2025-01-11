# DNS Tunnel

## Testing

### Setup Testing Environment

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
```

2. Install development dependencies:
```bash
pip install -r requirements-dev.txt
```

### Running Tests

To run all tests with coverage report:
```bash
PYTHONPATH=$PYTHONPATH:. pytest
```

Note: Setting `PYTHONPATH` is required to ensure the tests can find and import the `dns_tunnel` module directly from its location.

This will:
- Run all unit and integration tests
- Generate a coverage report in the terminal
- Create an HTML coverage report in the `htmlcov` directory

### Coverage Report

To view the detailed coverage report:
1. Run the tests as described above
2. Open `htmlcov/index.html` in your web browser
