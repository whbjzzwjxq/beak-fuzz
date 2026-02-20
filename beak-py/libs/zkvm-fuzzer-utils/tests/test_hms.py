from zkvm_fuzzer_utils.common import parse_hms_as_seconds


def test_parse_hms_as_seconds():
    malformed_input = parse_hms_as_seconds("")
    assert malformed_input is None, "hms input '\"\"'"

    malformed_input = parse_hms_as_seconds("h1abc")
    assert malformed_input is None, "hms input '\"h1abc\"'"

    malformed_input = parse_hms_as_seconds("h1h1")
    assert malformed_input is None, "hms input '\"h1h1\"'"

    hms_ones = parse_hms_as_seconds("h1m1s1")
    assert hms_ones == 3661, "hms input '\"h1m1s1\"'"

    hms_ones = parse_hms_as_seconds("h0001m001s01")
    assert hms_ones == 3661, "hms input '\"h0001m001s01\"'"

    hms_only_s = parse_hms_as_seconds("s10")
    assert hms_only_s == 10, "hms input '\"s10\"'"

    hms_only_m = parse_hms_as_seconds("m10")
    assert hms_only_m == 600, "hms input '\"m10\"'"

    hms_only_h = parse_hms_as_seconds("h2")
    assert hms_only_h == 7200, "hms input '\"h2\"'"
