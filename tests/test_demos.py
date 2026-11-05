from vulnscope.demos import available_demos, load_demo


def test_five_demos_exist():
    assert len(available_demos()) >= 5


def test_all_demos_provenance():
    for path in available_demos():
        scan = load_demo(path)
        assert scan["kind"] == "recorded-local-lab-scan"
        assert scan["target"] == "127.0.0.1"
        assert isinstance(scan["ports"], list)
