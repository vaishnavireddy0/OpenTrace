# OpenTrace

**Understand your codebase.**

OpenTrace is a Python codebase analysis tool that helps developers inspect project structure and identify maintainability issues.

## Features

- Upload ZIP files containing Python source code
- Analyze Python syntax and code structure
- Find TODO and FIXME comments
- Detect deeply nested conditions
- Identify potentially long functions
- Estimate code complexity
- Display findings by severity
- Export reports as JSON
- Explore a built-in demo project

## How It Works

OpenTrace reads Python source files as text and parses their syntax. It does not execute uploaded code.

Its findings are code-quality signals, not proof of security or complete code correctness.

## Requirements

- Python 3
- Flask

## Run Locally

```bash
git clone YOUR_REPOSITORY_URL
cd OpenTrace
python3 -m venv venv
source venv/bin/activate
python -m pip install flask
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## Privacy

Only upload source code you are authorized to share. Do not upload confidential code to shared or publicly hosted instances.

## Current Scope

The current prototype focuses on Python projects. Review analysis results before making code changes.

## License

A license has not yet been selected.
