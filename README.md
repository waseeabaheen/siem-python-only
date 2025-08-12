
# Python-Only SIEM Lab (Windows-friendly)
No Docker needed. Generates logs, normalizes into SQLite, runs detections, outputs HTML report.

## Contact
Author: Waseea Baheen
[Waseea Baheen}(mailto:waseea.baheen@gmail.com)

## Quickstart (PowerShell)
```powershell
Expand-Archive .\siem-python-only.zip -DestinationPath .
cd .\siem-python-only
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python scripts/generate_logs.py --minutes 2 --burst brute_force --traffic web
python scripts/ingest.py
python scripts/detections.py
Start-Process .\reports\siem_report.html
```

