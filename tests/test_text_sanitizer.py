from app.services.text_sanitizer import sanitize_user_text


def test_sanitize_removes_script_and_markup() -> None:
    raw = '<b>Hello</b><script>alert(1)</script><i>World</i>'
    assert sanitize_user_text(raw) == 'HelloWorld'


def test_sanitize_handles_none_and_length_limit() -> None:
    assert sanitize_user_text(None) == ''
    assert sanitize_user_text('x' * 10, max_length=4) == 'xxxx'
