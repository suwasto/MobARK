"""Vendored semgrep rule metadata loader (Aug 13 follow-up: the no-AI report
explanation cites a rule's ``metadata.summary`` - a description DISTINCT from
the finding title, so the deterministic text reads richer than a bare
tool/severity line)."""

from app.analysis import rule_meta


def test_mastg_rule_summary_indexed():
    """A MASTG rule's metadata.summary is the cited description."""
    assert rule_meta.rule_description("mastg-android-sdk-version") == (
        "This rule scans for API that checks the version of the operating system"
    )


def test_message_only_rule_has_no_description():
    """The hand-curated MobARK rules carry no metadata.summary - their folded
    message IS the finding title already, so citing it would just repeat the
    row (the finding's own title line renders it)."""
    assert rule_meta.rule_description("mobark-android-webview-javascript-enabled") is None


def test_unknown_or_missing_rule_is_none():
    assert rule_meta.rule_description(None) is None
    assert rule_meta.rule_description("no-such-rule") is None


def test_check_id_format_drift_suffix_match():
    """semgrep can report namespaced / path-prefixed check ids - the trailing
    rule id still resolves (``rules/foo.yml:<id>`` / ``rules.<id>``)."""
    desc = "This rule scans for API that checks the version of the operating system"
    assert rule_meta.rule_description("rules/foo.yml:mastg-android-sdk-version") == desc
    assert rule_meta.rule_description("rules.mastg-android-sdk-version") == desc


def test_summaries_collapsed_to_one_line():
    """Descriptions land in a single block-quote paragraph - no embedded
    newlines leak into the markdown."""
    for value in rule_meta.rule_descriptions().values():
        assert "\n" not in value
        assert value.strip() == value
