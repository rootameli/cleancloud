# modules_LeanCloud/__init__.py
import os
import json

def _load_patterns_from_json(base_dir: str):
    """
    Optionnel : si ton prof a fourni un fichier patterns.json dans modules_LeanCloud,
    on le charge et on le renvoie.
    Format attendu (exemple) :
      [
        {"name":"AWS Key", "regex":"AKIA[0-9A-Z]{16}", "severity":"high"},
        ...
      ]
    """
    p = os.path.join(base_dir, "patterns.json")
    if not os.path.exists(p):
        return []
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []

def register(loader):
    base_dir = os.path.dirname(__file__)

    # 1) Patterns (si patterns.json existe)
    patterns = _load_patterns_from_json(base_dir)

    # 2) Validators/Enrichers : on laisse vide pour l’instant (pas besoin de modifier le reste du repo)
    validators = []
    enrichers = []

    # Log simple dans les logs docker (preuve que c'est branché)
    print(f"✅ modules_LeanCloud.register() loaded. patterns={len(patterns)}")

    return {
        "LeanCloudPack": {
            "patterns": patterns,
            "validators": validators,
            "enrichers": enrichers,
        }
    }

