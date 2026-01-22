SpaceX Task Notes

Quick run (Windows):
1) python -m venv .venv
2) .\.venv\Scripts\python -m pip install -r requirements.txt
3) .\.venv\Scripts\python spacex.py --action report

Examples:
- .\.venv\Scripts\python spacex.py --action payloads -v
- .\.venv\Scripts\python spacex.py --action launchpads --refresh --cache .cache\launches.json
