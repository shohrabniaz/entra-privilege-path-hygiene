Set-Location (Split-Path -Parent $PSScriptRoot)
python -m src.cli analyse --path .\data\sample_directory.csv
python tests\test_smoke.py
