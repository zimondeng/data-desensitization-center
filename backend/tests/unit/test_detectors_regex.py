from app.detectors import DetectedSpan, detect_regex_spans


def test_cn_id_card_accepts_valid_checksum_including_upper_and_lower_x() -> None:
    text = (
        "申请人身份证32040219900307118X，"
        "配偶11010519491231002x，"
        "家属320402199003071235已核验"
    )

    spans = detect_regex_spans(text, enabled_labels={"cn_id_card"})

    assert [(s.label, text[s.start : s.end], s.score, s.detector) for s in spans] == [
        ("cn_id_card", "32040219900307118X", 1.0, "regex"),
        ("cn_id_card", "11010519491231002x", 1.0, "regex"),
        ("cn_id_card", "320402199003071235", 1.0, "regex"),
    ]
    assert all(isinstance(s, DetectedSpan) for s in spans)


def test_cn_id_card_rejects_wrong_check_digit_and_impossible_calendar_date() -> None:
    # 32040219900307123X has valid check digit '5', not 'X'
    # 320402199002301182 has valid mod-11 check digit '2' but impossible date 1990-02-30
    bad_checksum = "32040219900307123X"
    bad_feb30 = "320402199002301182"
    embedded_in_alnum = "A32040219900307118XB"
    text = f"错误校验位：{bad_checksum}；非法日期：{bad_feb30}；粘连字母：{embedded_in_alnum}"

    spans = detect_regex_spans(text, enabled_labels={"cn_id_card"})

    assert spans == []


def test_cn_uscc_validates_mod31_and_excludes_forbidden_letters() -> None:
    text = (
        "企业信用代码91350100M000100Y43，"
        "零余数边界91350100M000100Y30，"
        "字母校验位91350100M000100Y7C；"
        "错误校验91350100M000100Y44；"
        "禁用字符91350100I000100Y43、91350100O000100Y43、91350100Z000100Y43、91350100S000100Y43、91350100V000100Y43"
    )

    spans = detect_regex_spans(text, enabled_labels={"cn_uscc"})

    assert [(s.label, text[s.start : s.end], s.score, s.detector) for s in spans] == [
        ("cn_uscc", "91350100M000100Y43", 1.0, "regex"),
        ("cn_uscc", "91350100M000100Y30", 1.0, "regex"),
        ("cn_uscc", "91350100M000100Y7C", 1.0, "regex"),
    ]


def test_cn_mobile_enforces_non_digit_boundaries_and_prefix() -> None:
    text = "联系电话13812345678，备用(19987654321)；非号段12812345678；超长013812345678与138123456789不命中"

    spans = detect_regex_spans(text, enabled_labels={"cn_mobile"})

    assert [(s.label, text[s.start : s.end], s.score, s.detector) for s in spans] == [
        ("cn_mobile", "13812345678", 1.0, "regex"),
        ("cn_mobile", "19987654321", 1.0, "regex"),
    ]


def test_bank_card_luhn_matches_16_to_19_digits_and_never_misclassifies_valid_id_cards() -> None:
    # 320402199003071251 is both a valid mod-11 cn_id_card AND passes Luhn mod-10.
    # 32040219900307118X is a valid cn_id_card whose 17-digit prefix passes Luhn mod-10.
    text = (
        "贷记卡6225880137700002，借记卡6222021202001234567；"
        "非法卡号6225880137700003、6222021202001234568；"
        "偶合Luhn身份证320402199003071251与末位X身份证32040219900307118X"
    )

    all_spans = detect_regex_spans(text)
    assert [(s.label, text[s.start : s.end]) for s in all_spans] == [
        ("bank_card_luhn", "6225880137700002"),
        ("bank_card_luhn", "6222021202001234567"),
        ("cn_id_card", "320402199003071251"),
        ("cn_id_card", "32040219900307118X"),
    ]

    bank_only_spans = detect_regex_spans(text, enabled_labels={"bank_card_luhn"})
    assert [(s.label, text[s.start : s.end]) for s in bank_only_spans] == [
        ("bank_card_luhn", "6225880137700002"),
        ("bank_card_luhn", "6222021202001234567"),
    ]

