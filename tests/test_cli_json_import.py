import mcpsec.cli as cli


def test_cli_has_json_module_import():
    assert hasattr(cli, "json")
    assert getattr(cli, "json").__name__ == "json"
