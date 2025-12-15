from app.core.modules_loader import ModulesLoader


def test_patterns_merge_from_registered_modules():
    loader = ModulesLoader()
    loader.registered_modules = {
        "sample": {
            "patterns": [
                {
                    "name": "Example",
                    "pattern": "abc123",
                    "description": "Sample",
                    "module_type": "generic",
                }
            ]
        }
    }

    patterns = loader.get_patterns()

    assert patterns and patterns[0]["name"] == "Example"
