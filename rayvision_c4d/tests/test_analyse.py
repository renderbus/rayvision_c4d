"""Test rayvision_c4d.analyse_c4d model."""


def test_get_file_md5(c4d):
    """Test print_info this interface."""
    info = "test print info"
    assert bool(c4d.get_file_md5(info))
