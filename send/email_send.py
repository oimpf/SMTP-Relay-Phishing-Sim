#!/usr/bin/env python3
import sys
import os
import stat
import ssl
import smtplib
import socket
import configparser
import argparse
import html as html_module
import getpass

from dataclasses import dataclass
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import (
    formatdate,
    make_msgid,
    parseaddr,
    getaddresses,
)


# ----------------------------
# Исключения приложения
# ----------------------------

class MailerError(Exception):
    """Базовая ошибка приложения."""


class ConfigError(MailerError):
    """Ошибка конфигурации."""


class SecurityError(MailerError):
    """Ошибка политики безопасности."""


class InputError(MailerError):
    """Ошибка входных данных."""


class BodyReadError(MailerError):
    """Ошибка чтения тела письма."""


class DeliveryError(MailerError):
    """Ошибка отправки письма."""


# ----------------------------
# Модель настроек
# ----------------------------

@dataclass
class SMTPSettings:
    server: str
    port: int
    from_addr: str
    default_to: str | None
    default_subject: str
    hta_url: str
    body_file: str | None
    username: str | None
    timeout: int
    use_tls: bool
    use_ssl: bool
    password_env: str | None
    password_in_config: str | None


# ----------------------------
# Вспомогательные функции
# ----------------------------

def eprint(message):
    print(message, file=sys.stderr)


def load_config(config_file):
    # ConfigParser работает с именами опций без учёта регистра:
    # SERVER, server и SeRvEr эквивалентны.
    config = configparser.ConfigParser()
    read_files = config.read(config_file, encoding='utf-8')
    if not read_files:
        raise ConfigError(f"конфиг {config_file} не найден")
    if 'SMTP' not in config:
        raise ConfigError("секция [SMTP] не найдена")

    if config_contains_password(config):
        check_config_permissions(config_file)

    return config


def config_contains_password(config):
    return config.has_option('SMTP', 'PASSWORD') and bool(
        config.get('SMTP', 'PASSWORD', fallback='').strip()
    )


def check_config_permissions(config_file):
    path = Path(config_file)

    if os.name == 'nt':
        return True

    try:
        st = path.stat()
    except OSError as e:
        raise SecurityError(f"не удалось проверить права на {config_file}: {e}") from e

    insecure_bits = stat.S_IWGRP | stat.S_IWOTH
    if st.st_mode & insecure_bits:
        raise SecurityError(
            f"небезопасные права на {config_file}: файл доступен на запись группе или другим пользователям"
        )

    return True


def get_bool_option(config, section, option, fallback=False):
    try:
        return config.getboolean(section, option, fallback=fallback)
    except ValueError as e:
        raise ConfigError(
            f"параметр [{section}] {option} должен быть true/false, yes/no, on/off или 1/0"
        ) from e


def extract_smtp_settings(config):
    required = ['SERVER', 'PORT', 'FROM']
    missing = [key for key in required if not config.has_option('SMTP', key)]
    if missing:
        raise ConfigError(
            f"в секции [SMTP] отсутствуют обязательные параметры: {', '.join(missing)}"
        )

    try:
        port = config.getint('SMTP', 'PORT')
    except ValueError as e:
        raise ConfigError("PORT должен быть числом от 1 до 65535") from e

    if not (1 <= port <= 65535):
        raise ConfigError("PORT должен быть числом от 1 до 65535")

    try:
        timeout = config.getint('SMTP', 'TIMEOUT', fallback=30)
    except ValueError as e:
        raise ConfigError("TIMEOUT должен быть положительным целым числом") from e

    if timeout <= 0:
        raise ConfigError("TIMEOUT должен быть положительным целым числом")

    use_tls = get_bool_option(config, 'SMTP', 'USE_TLS', fallback=False)
    use_ssl = get_bool_option(config, 'SMTP', 'USE_SSL', fallback=False)

    if use_tls and use_ssl:
        raise ConfigError("нельзя одновременно включить USE_TLS и USE_SSL")

    return SMTPSettings(
        server=config.get('SMTP', 'SERVER'),
        port=port,
        from_addr=config.get('SMTP', 'FROM'),
        default_to=config.get('SMTP', 'TO', fallback=None),
        default_subject=config.get('SMTP', 'SUBJECT', fallback='(без темы)'),
        hta_url=config.get('SMTP', 'HTA_URL', fallback=''),
        body_file=config.get('SMTP', 'BODY_FILE', fallback=None),
        username=config.get('SMTP', 'USERNAME', fallback=None),
        timeout=timeout,
        use_tls=use_tls,
        use_ssl=use_ssl,
        password_env=config.get('SMTP', 'PASSWORD_ENV', fallback=None),
        password_in_config=config.get('SMTP', 'PASSWORD', fallback=None),
    )


def get_smtp_password(settings, prompt_if_missing=False):
    if settings.password_env:
        env_password = os.environ.get(settings.password_env)
        if env_password is None:
            raise ConfigError(
                f"переменная окружения {settings.password_env} указана в PASSWORD_ENV, но не задана"
            )
        return env_password

    env_password = os.environ.get('SMTP_PASSWORD')
    if env_password is not None:
        return env_password

    if settings.password_in_config:
        eprint("[!] Предупреждение: пароль SMTP загружается из config.ini в открытом виде")
        return settings.password_in_config

    if prompt_if_missing:
        return getpass.getpass("SMTP password: ")

    return None


def check_security_policy(settings, debug=False, allow_insecure=False, prompt_password=False):
    password = get_smtp_password(settings, prompt_if_missing=prompt_password)
    has_auth = bool(settings.username and password)

    if debug and has_auth:
        raise SecurityError(
            "нельзя использовать --debug при SMTP-аутентификации: SMTP-диалог может раскрыть credentials"
        )

    if has_auth and not settings.use_tls and not settings.use_ssl:
        if not allow_insecure:
            raise SecurityError(
                "SMTP-аутентификация без TLS/SSL запрещена. "
                "Включите USE_TLS/USE_SSL или используйте --allow-insecure"
            )
        eprint("[!] Предупреждение: SMTP-аутентификация будет передана без TLS/SSL в открытом виде")


def apply_placeholders(text, hta_url):
    return text.replace('{hta_url}', hta_url)


def read_body_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError as e:
        raise BodyReadError(f"файл {file_path} не найден") from e
    except OSError as e:
        raise BodyReadError(f"ошибка при чтении файла {file_path}: {e}") from e


def resolve_message_text(text_override, body_file, hta_url):
    if text_override is not None:
        return apply_placeholders(text_override, hta_url)

    if body_file:
        return apply_placeholders(read_body_file(body_file), hta_url)

    raise InputError("не указан текст письма и BODY_FILE")


def text_to_html(text):
    html_text = html_module.escape(text).replace('\n', '<br>\n')
    return f"""<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: Arial, sans-serif;">
{html_text}
</body>
</html>"""


def is_valid_email(address):
    if not address or not address.strip():
        return False

    _, email_addr = parseaddr(address)
    if not email_addr or '@' not in email_addr:
        return False

    local_part, _, domain_part = email_addr.rpartition('@')
    if not local_part or not domain_part:
        return False

    if ' ' in email_addr:
        return False

    return True


def parse_recipients(to_addr):
    if to_addr is None:
        raise InputError("поле TO не задано")

    parsed = getaddresses([to_addr])
    recipients = [email for _, email in parsed if email and email.strip()]

    if not recipients:
        raise InputError("поле TO не содержит ни одного корректного адреса")

    return recipients


def validate_email_addresses(from_addr, recipients):
    if not is_valid_email(from_addr):
        raise InputError(f"некорректный адрес отправителя: {from_addr!r}")

    invalid = [addr for addr in recipients if not is_valid_email(addr)]
    if invalid:
        raise InputError(
            f"некорректные адреса получателей: {', '.join(repr(x) for x in invalid)}"
        )


def build_message(from_addr, to_header, subject, text, html_body):
    msg = MIMEMultipart("alternative")
    msg["From"] = from_addr
    msg["To"] = to_header
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    msg.attach(MIMEText(text, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    return msg


def create_smtp_client(settings, debug=False):
    server = None
    context = None

    if settings.use_tls or settings.use_ssl:
        try:
            context = ssl.create_default_context()
        except ssl.SSLError as e:
            raise DeliveryError(f"не удалось создать SSL-контекст: {e}") from e
        except OSError as e:
            raise DeliveryError(f"ошибка при инициализации SSL-контекста: {e}") from e

    try:
        if settings.use_ssl:
            server = smtplib.SMTP_SSL(
                settings.server,
                settings.port,
                timeout=settings.timeout,
                context=context,
            )
        else:
            server = smtplib.SMTP(
                settings.server,
                settings.port,
                timeout=settings.timeout,
            )

        if debug:
            server.set_debuglevel(True)

        try:
            server.ehlo()
        except smtplib.SMTPHeloError as e:
            raise DeliveryError(f"ошибка SMTP на этапе EHLO: {e}") from e
        except smtplib.SMTPException as e:
            raise DeliveryError(f"ошибка SMTP при выполнении EHLO: {e}") from e

        if settings.use_tls:
            try:
                server.starttls(context=context)
            except ssl.SSLError as e:
                raise DeliveryError(f"ошибка TLS/SSL при выполнении STARTTLS: {e}") from e
            except smtplib.SMTPException as e:
                raise DeliveryError(f"ошибка SMTP при запуске STARTTLS: {e}") from e

            try:
                server.ehlo()
            except smtplib.SMTPHeloError as e:
                raise DeliveryError(f"ошибка SMTP на этапе EHLO после STARTTLS: {e}") from e
            except smtplib.SMTPException as e:
                raise DeliveryError(f"ошибка SMTP при выполнении EHLO после STARTTLS: {e}") from e

        return server

    except socket.gaierror as e:
        if server is not None:
            try:
                server.close()
            except Exception:
                pass
        raise DeliveryError(f"не удалось разрешить имя хоста {settings.server}: {e}") from e
    except OSError as e:
        if server is not None:
            try:
                server.close()
            except Exception:
                pass
        raise DeliveryError(
            f"сетевая ошибка при подключении к {settings.server}:{settings.port}: {e}"
        ) from e
    except Exception:
        if server is not None:
            try:
                server.close()
            except Exception:
                pass
        raise


def compose_message(settings, to_override=None, subject_override=None, text_override=None):
    to_addr = to_override if to_override is not None else settings.default_to
    subject = subject_override if subject_override is not None else settings.default_subject

    if not to_addr:
        raise InputError("не указан получатель (TO или --to)")

    recipients = parse_recipients(to_addr)
    validate_email_addresses(settings.from_addr, recipients)

    text = resolve_message_text(text_override, settings.body_file, settings.hta_url)
    html_body = text_to_html(text)

    to_header = ", ".join(recipients)
    msg = build_message(
        from_addr=settings.from_addr,
        to_header=to_header,
        subject=subject,
        text=text,
        html_body=html_body,
    )

    return msg, recipients, text, html_body


def send_email(settings, to_override=None, subject_override=None,
               text_override=None, dry_run=False, debug=False,
               prompt_password=False, allow_insecure=False):
    check_security_policy(
        settings,
        debug=debug,
        allow_insecure=allow_insecure,
        prompt_password=prompt_password,
    )

    msg, recipients, text, html_body = compose_message(
        settings=settings,
        to_override=to_override,
        subject_override=subject_override,
        text_override=text_override,
    )

    if dry_run:
        print("\n" + "=" * 60)
        print("РЕЖИМ ПРОВЕРКИ (письмо не отправлено)")
        print("=" * 60)
        print(f"\nSMTP: {settings.server}:{settings.port}")
        print("\n--- MIME MESSAGE ---")
        sys.stdout.buffer.write(msg.as_bytes())
        print("\n" + "=" * 60)
        return True

    server = None
    try:
        server = create_smtp_client(settings, debug=debug)

        password = get_smtp_password(settings, prompt_if_missing=prompt_password)
        if settings.username and password:
            server.login(settings.username, password)
        elif settings.username and not password:
            raise SecurityError("указан USERNAME, но пароль не задан")

        server.send_message(msg, from_addr=settings.from_addr, to_addrs=recipients)
        print(f"[+] Письмо успешно отправлено на {msg['To']}")
        return True

    except smtplib.SMTPAuthenticationError as e:
        raise DeliveryError(f"ошибка аутентификации: {e}") from e
    except smtplib.SMTPConnectError as e:
        raise DeliveryError(f"ошибка подключения: {e}") from e
    except smtplib.SMTPRecipientsRefused as e:
        raise DeliveryError(f"получатели отклонены сервером: {e}") from e
    except smtplib.SMTPSenderRefused as e:
        raise DeliveryError(f"адрес отправителя отклонён сервером: {e}") from e
    except smtplib.SMTPDataError as e:
        raise DeliveryError(f"ошибка при передаче данных письма: {e}") from e
    except smtplib.SMTPHeloError as e:
        raise DeliveryError(f"ошибка SMTP-приветствия (HELO/EHLO): {e}") from e
    except smtplib.SMTPException as e:
        raise DeliveryError(f"SMTP ошибка: {e}") from e
    except ConnectionRefusedError as e:
        raise DeliveryError(
            f"соединение отклонено {settings.server}:{settings.port}"
        ) from e
    except TimeoutError as e:
        raise DeliveryError(
            f"таймаут подключения к {settings.server}:{settings.port}"
        ) from e
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass


def apply_cli_overrides(config, args):
    if args.server is not None:
        if not args.server.strip():
            raise InputError("--server не может быть пустым")
        config.set('SMTP', 'SERVER', args.server)

    if args.port is not None:
        config.set('SMTP', 'PORT', str(args.port))

    if args.from_addr is not None:
        if not args.from_addr.strip():
            raise InputError("--from не может быть пустым")
        config.set('SMTP', 'FROM', args.from_addr)

    if args.url is not None:
        config.set('SMTP', 'HTA_URL', args.url)

    if args.username is not None:
        config.set('SMTP', 'USERNAME', args.username)

    if args.password is not None:
        eprint("[!] Предупреждение: значение --password видно в списке процессов")
        config.set('SMTP', 'PASSWORD', args.password)

    if args.password_env is not None:
        if not args.password_env.strip():
            raise InputError("--password-env не может быть пустым")
        config.set('SMTP', 'PASSWORD_ENV', args.password_env)

    if args.body_file is not None:
        if not args.body_file.strip():
            raise InputError("--body-file не может быть пустым")
        config.set('SMTP', 'BODY_FILE', args.body_file)

    if args.timeout is not None:
        config.set('SMTP', 'TIMEOUT', str(args.timeout))

    if args.tls:
        config.set('SMTP', 'USE_TLS', 'true')
        config.set('SMTP', 'USE_SSL', 'false')

    if args.ssl:
        config.set('SMTP', 'USE_SSL', 'true')
        config.set('SMTP', 'USE_TLS', 'false')


def parse_args():
    parser = argparse.ArgumentParser(description='Отправка SMTP письма')
    parser.add_argument('-c', '--config', default='config.ini', help='Путь к config.ini')
    parser.add_argument('-t', '--to', help='Получатель/получатели')
    parser.add_argument('-s', '--subject', help='Тема письма')
    parser.add_argument('--text', help='Текст письма (небезопасно: виден в списке процессов)')
    parser.add_argument('--stdin', action='store_true', help='Прочитать текст письма из stdin')
    parser.add_argument('--server', help='SMTP сервер')
    parser.add_argument('--port', type=int, help='SMTP порт')
    parser.add_argument('--from', dest='from_addr', help='Адрес отправителя')
    parser.add_argument('--url', help='Значение для подстановки {hta_url}')
    parser.add_argument('--username', help='SMTP логин')
    parser.add_argument('--password', help='SMTP пароль (небезопасно: виден в списке процессов)')
    parser.add_argument('--password-env', help='Имя переменной окружения для SMTP пароля')
    parser.add_argument('--body-file', help='Путь к файлу с текстом письма')
    parser.add_argument('--timeout', type=int, help='Таймаут подключения/отправки в секундах')
    parser.add_argument('--ask-password', action='store_true', help='Запросить SMTP пароль интерактивно')
    parser.add_argument('--allow-insecure', action='store_true', help='Разрешить SMTP-аутентификацию без TLS/SSL')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--tls', action='store_true', help='Включить STARTTLS')
    group.add_argument('--ssl', action='store_true', help='Использовать SMTP_SSL')
    parser.add_argument('--dry-run', action='store_true', help='Показать полное MIME-письмо без отправки')
    parser.add_argument('--debug', action='store_true', help='Включить SMTP debug (опасно при AUTH)')
    return parser.parse_args()


def main():
    try:
        args = parse_args()

        if args.text is not None and args.stdin:
            raise InputError("нельзя одновременно использовать --text и --stdin")

        if args.text is not None:
            eprint("[!] Предупреждение: значение --text видно в списке процессов")

        text_override = args.text
        if args.stdin:
            text_override = sys.stdin.read()

        config = load_config(args.config)
        apply_cli_overrides(config, args)
        settings = extract_smtp_settings(config)

        success = send_email(
            settings=settings,
            to_override=args.to,
            subject_override=args.subject,
            text_override=text_override,
            dry_run=args.dry_run,
            debug=args.debug,
            prompt_password=args.ask_password,
            allow_insecure=args.allow_insecure,
        )

        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        eprint("\n[-] Прервано пользователем")
        sys.exit(130)
    except MailerError as e:
        eprint(f"[-] Ошибка: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
