import configparser
from pathlib import Path
from unittest.mock import Mock

import pytest

import send_mail


def make_config(**overrides):
    config = configparser.ConfigParser()
    config['SMTP'] = {
        'SERVER': 'smtp.example.com',
        'PORT': '587',
        'FROM': 'sender@example.com',
        'TO': 'recipient@example.com',
        'SUBJECT': 'Test subject',
        'USE_TLS': 'false',
        'USE_SSL': 'false',
        'USERNAME': '',
        'PASSWORD': '',
        'HTA_URL': 'https://example.com/test.hta',
        'BODY_FILE': '',
        'TIMEOUT': '30',
    }

    for key, value in overrides.items():
        config['SMTP'][key] = str(value)

    return config


def test_text_to_html_escapes_html():
    text = "<b>Hello</b>\nWorld"
    html = send_mail.text_to_html(text)

    assert "&lt;b&gt;Hello&lt;/b&gt;" in html
    assert "<br>" in html
    assert "<b>Hello</b>" not in html


def test_parse_recipients_single():
    recipients = send_mail.parse_recipients("user@example.com")
    assert recipients == ["user@example.com"]


def test_parse_recipients_multiple():
    recipients = send_mail.parse_recipients("a@example.com, b@example.com , c@example.com")
    assert recipients == ["a@example.com", "b@example.com", "c@example.com"]


def test_parse_recipients_ignores_empty_entries():
    recipients = send_mail.parse_recipients("a@example.com, , b@example.com, ")
    assert recipients == ["a@example.com", "b@example.com"]


def test_parse_recipients_raises_on_empty():
    with pytest.raises(ValueError, match="не содержит ни одного корректного адреса"):
        send_mail.parse_recipients(" ,   , ")


def test_read_body_file_replaces_hta_url(tmp_path):
    body_file = tmp_path / "body.txt"
    body_file.write_text("Link: {hta_url}", encoding="utf-8")

    result = send_mail.read_body_file(str(body_file), "https://example.com/file.hta")
    assert result == "Link: https://example.com/file.hta"


def test_read_body_file_not_found():
    result = send_mail.read_body_file("no_such_file.txt", "https://example.com/file.hta")
    assert result is None


def test_build_message_contains_headers_and_parts():
    msg = send_mail.build_message(
        from_addr="sender@example.com",
        to_addr="recipient@example.com",
        subject="Hello",
        text="Plain text",
        html_body="<html><body>HTML</body></html>"
    )

    assert msg["From"] == "sender@example.com"
    assert msg["To"] == "recipient@example.com"
    assert msg["Subject"] == "Hello"
    assert msg.is_multipart()

    payload = msg.get_payload()
    assert len(payload) == 2
    assert payload[0].get_content_type() == "text/plain"
    assert payload[1].get_content_type() == "text/html"


def test_validate_config_ok():
    config = make_config()
    send_mail.validate_config(config)


def test_validate_config_missing_required(monkeypatch):
    config = configparser.ConfigParser()
    config['SMTP'] = {
        'PORT': '587',
        'FROM': 'sender@example.com',
    }

    with pytest.raises(SystemExit) as exc:
        send_mail.validate_config(config)

    assert exc.value.code == 1


def test_validate_config_invalid_port():
    config = make_config(PORT="99999")

    with pytest.raises(SystemExit) as exc:
        send_mail.validate_config(config)

    assert exc.value.code == 1


def test_send_email_dry_run_with_text(capsys):
    config = make_config()

    result = send_mail.send_email(
        config=config,
        text_override="Hello dry run",
        dry_run=True
    )

    captured = capsys.readouterr()
    assert result is True
    assert "РЕЖИМ ПРОВЕРКИ" in captured.out
    assert "Hello dry run" in captured.out


def test_send_email_fails_without_text_and_body_file(capsys):
    config = make_config(BODY_FILE='')

    result = send_mail.send_email(config=config)

    captured = capsys.readouterr()
    assert result is False
    assert "Не указан текст письма и BODY_FILE" in captured.err


def test_send_email_uses_body_file(tmp_path, monkeypatch):
    body_file = tmp_path / "body.txt"
    body_file.write_text("Hello {hta_url}", encoding="utf-8")

    config = make_config(BODY_FILE=str(body_file), HTA_URL="https://test.local/file.hta")

    fake_server = Mock()
    monkeypatch.setattr(send_mail, "create_smtp_client", lambda config, debug=False: fake_server)

    result = send_mail.send_email(config=config)

    assert result is True
    fake_server.sendmail.assert_called_once()

    args, kwargs = fake_server.sendmail.call_args
    from_addr, recipients, raw_message = args

    assert from_addr == "sender@example.com"
    assert recipients == ["recipient@example.com"]
    assert "Hello" in raw_message
    assert "https://test.local/file.hta" in raw_message


def test_send_email_logs_in_when_credentials_present(monkeypatch):
    config = make_config(USERNAME="user", PASSWORD="pass")

    fake_server = Mock()
    monkeypatch.setattr(send_mail, "create_smtp_client", lambda config, debug=False: fake_server)

    result = send_mail.send_email(config=config, text_override="Hello")

    assert result is True
    fake_server.login.assert_called_once_with("user", "pass")
    fake_server.sendmail.assert_called_once()


def test_send_email_does_not_login_without_credentials(monkeypatch):
    config = make_config(USERNAME="", PASSWORD="")

    fake_server = Mock()
    monkeypatch.setattr(send_mail, "create_smtp_client", lambda config, debug=False: fake_server)

    result = send_mail.send_email(config=config, text_override="Hello")

    assert result is True
    fake_server.login.assert_not_called()
    fake_server.sendmail.assert_called_once()


def test_send_email_handles_invalid_recipient_string(capsys):
    config = make_config(TO=" , ")

    result = send_mail.send_email(config=config, text_override="Hello")

    captured = capsys.readouterr()
    assert result is False
    assert "не содержит ни одного корректного адреса" in captured.err


def test_send_email_handles_smtp_auth_error(monkeypatch, capsys):
    config = make_config(USERNAME="user", PASSWORD="pass")

    class FakeServer:
        def login(self, username, password):
            raise send_mail.smtplib.SMTPAuthenticationError(535, b'Auth failed')

        def quit(self):
            pass

    monkeypatch.setattr(send_mail, "create_smtp_client", lambda config, debug=False: FakeServer())

    result = send_mail.send_email(config=config, text_override="Hello")

    captured = capsys.readouterr()
    assert result is False
    assert "Ошибка аутентификации" in captured.err


def test_send_email_calls_quit_on_success(monkeypatch):
    config = make_config()

    fake_server = Mock()
    monkeypatch.setattr(send_mail, "create_smtp_client", lambda config, debug=False: fake_server)

    result = send_mail.send_email(config=config, text_override="Hello")

    assert result is True
    fake_server.quit.assert_called_once()


def test_create_smtp_client_uses_starttls(monkeypatch):
    config = make_config(USE_TLS='true', USE_SSL='false')

    fake_smtp = Mock()
    smtp_ctor = Mock(return_value=fake_smtp)
    monkeypatch.setattr(send_mail.smtplib, "SMTP", smtp_ctor)

    server = send_mail.create_smtp_client(config, debug=True)

    assert server is fake_smtp
    smtp_ctor.assert_called_once_with("smtp.example.com", 587, timeout=30)
    fake_smtp.set_debuglevel.assert_called_once_with(True)
    assert fake_smtp.ehlo.call_count == 2
    fake_smtp.starttls.assert_called_once()


def test_create_smtp_client_uses_ssl(monkeypatch):
    config = make_config(USE_TLS='false', USE_SSL='true')

    fake_smtp_ssl = Mock()
    smtp_ssl_ctor = Mock(return_value=fake_smtp_ssl)
    monkeypatch.setattr(send_mail.smtplib, "SMTP_SSL", smtp_ssl_ctor)

    server = send_mail.create_smtp_client(config)

    assert server is fake_smtp_ssl
    smtp_ssl_ctor.assert_called_once()
    fake_smtp_ssl.ehlo.assert_called_once()


def test_create_smtp_client_rejects_tls_and_ssl_together():
    config = make_config(USE_TLS='true', USE_SSL='true')

    with pytest.raises(ValueError, match="нельзя одновременно включить USE_TLS и USE_SSL"):
        send_mail.create_smtp_client(config)