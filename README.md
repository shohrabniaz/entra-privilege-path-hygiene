# Entra privilege-path hygiene

**Author:** Md Shohrab Hossen Niaz

Analyse **exported** directory CSVs for standing Global Admin on daily UPNs and disabled accounts still in privileged groups.

```powershell
python -m src.cli analyse --path .\data\sample_directory.csv
```
