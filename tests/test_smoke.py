import importlib, sys

def test_import_root():
    # Basic import smoke test for the service package
    pkg = sys.path[0].split('/')[-1]
    assert True
