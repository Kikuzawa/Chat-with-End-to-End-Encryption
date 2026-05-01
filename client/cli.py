#!/usr/bin/env python3
"""
🔐 Защищённый E2EE чат с сквозным шифрованием
Протокол: X3DH + Double Ratchet + AES-256-GCM
"""
import asyncio
import argparse
import json
import sys
import os
import traceback
from pathlib import Path
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from client.networkclient import NetworkClient
from crypto.keymanager import KeyManager
from crypto.sessionmanager import SessionManager, RatchetState
from crypto.messagecrypto import MessageCrypto
from crypto.contactverifier import ContactVerifier
import base64

# ─── Цветовые коды ───────────────────────────────────────────
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE = "\033[44m"

# ─── Функции форматирования ──────────────────────────────────
def timestamp():
    return datetime.now().strftime("%H:%M:%S")

def info(msg):
    print(f"{Colors.DIM}[{timestamp()}]{Colors.RESET} {Colors.BLUE}[INFO]{Colors.RESET} {msg}")

def success(msg):
    print(f"{Colors.DIM}[{timestamp()}]{Colors.RESET} {Colors.GREEN}[OK]{Colors.RESET}  {msg}")

def error(msg):
    print(f"{Colors.DIM}[{timestamp()}]{Colors.RESET} {Colors.RED}[ERR]{Colors.RESET} {msg}")

def warn(msg):
    print(f"{Colors.DIM}[{timestamp()}]{Colors.RESET} {Colors.YELLOW}[WARN]{Colors.RESET} {msg}")

def header(msg):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'─'*50}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}  {msg}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'─'*50}{Colors.RESET}\n")

def fingerprint_display(fp):
    """Красивый вывод фингерпринта"""
    return f"{Colors.YELLOW}{fp[:8]}{Colors.RESET}"

def incoming_msg(sender, text, msg_type=""):
    """Форматирование входящего сообщения"""
    type_indicator = ""
    if msg_type == "prekey":
        type_indicator = f" {Colors.DIM}[X3DH]{Colors.RESET}"
    
    print(f"\n{Colors.GREEN}╭─[{timestamp()}] {Colors.BOLD}{sender}{Colors.RESET}{type_indicator}")
    print(f"{Colors.GREEN}╰─> {Colors.RESET}{text}")

def outgoing_msg(recipient, text, status="sent"):
    """Форматирование исходящего сообщения"""
    status_color = Colors.GREEN if status == "sent" else Colors.RED
    print(f"\n{Colors.BLUE}╭─[{timestamp()}] {Colors.BOLD}Вы -> {recipient}{Colors.RESET}")
    print(f"{Colors.BLUE}╰─> {Colors.RESET}{text} {Colors.DIM}[{status_color}{status}{Colors.DIM}]{Colors.RESET}")

# ─── Глобальные переменные ───────────────────────────────────
SERVER_URL = os.getenv("SERVER_URL", "ws://localhost:8000/ws")
sessions = {}

# ─── Инициализация клиента ───────────────────────────────────
async def init_client(username=None):
    key_path = Path.home() / ".secure-chat" / f"{username}_keys.json" if username else Path.home() / ".secure-chat" / "keys.json"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    keyman = KeyManager(str(key_path))
    
    if key_path.exists():
        try:
            keyman = KeyManager.load_keys(str(key_path))
            info(f"Загружены ключи пользователя {Colors.BOLD}{keyman.username}{Colors.RESET}")
            fp = ContactVerifier.fingerprint(keyman.ik_x25519_pub)
            info(f"Отпечаток IK: {fingerprint_display(fp)}")
            return keyman
        except Exception as e:
            warn(f"Ошибка загрузки ключей: {e}")
            info("Создаю новые ключи...")
    
    keyman.generate_identity_key()
    keyman.generate_spk()
    keyman.generate_opks(10)
    
    if not username:
        username = input(f"{Colors.CYAN}Введите имя пользователя:{Colors.RESET} ").strip()
        if not username:
            error("Имя пользователя не может быть пустым")
            sys.exit(1)
    
    keyman.username = username
    keyman.save_keys(username)
    
    fp = ContactVerifier.fingerprint(keyman.ik_x25519_pub)
    header(f"НОВЫЙ ПОЛЬЗОВАТЕЛЬ: {Colors.BOLD}{username}{Colors.RESET}")
    info(f"Отпечаток IK: {fingerprint_display(fp)}")
    print(f"  {Colors.DIM}(Сохраните этот отпечаток для верификации контакта){Colors.RESET}")
    
    return keyman

async def get_password(args, prompt="Пароль: "):
    if args.password:
        return args.password
    return input(f"{Colors.CYAN}{prompt}{Colors.RESET}").strip()

# ─── Основная логика ─────────────────────────────────────────
async def login_and_run(cm: KeyManager, args):
    nc = NetworkClient(SERVER_URL)
    try:
        await nc.connect()
        password = await get_password(args)
        
        if args.command != "register":
            ok = await nc.login(cm.username, password)
            if not ok:
                error("Ошибка входа. Проверьте имя пользователя и пароль.")
                return
            success(f"Вход выполнен как {Colors.BOLD}{cm.username}{Colors.RESET}")

        async def on_message(sender, data):
            try:
                msg_type = data.get("type", "message")
                
                if sender not in sessions:
                    if msg_type == "prekey":
                        init_ik_pub = base64.b64decode(data["ik_a_pub"])
                        init_ek_pub = base64.b64decode(data["ek_a_pub"])
                        
                        state = SessionManager.receive_session(
                            cm.ik_x25519_priv,
                            cm.ik_x25519_pub,
                            cm.spk_priv,
                            cm.spk_pub,
                            {},
                            init_ik_pub,
                            init_ek_pub,
                            None
                        )
                        sessions[sender] = state
                        
                        ciphertext = base64.b64decode(data["ciphertext"])
                        header = data["header"]
                        plain = SessionManager.decrypt_from_session(state, ciphertext, header)
                        incoming_msg(sender, plain.decode(), "prekey")
                    else:
                        error(f"Получено сообщение неизвестного типа: {msg_type}")
                else:
                    state = sessions[sender]
                    ciphertext = base64.b64decode(data["ciphertext"])
                    header = data["header"]
                    plain = SessionManager.decrypt_from_session(state, ciphertext, header)
                    incoming_msg(sender, plain.decode())
            except Exception as e:
                error(f"Ошибка расшифровки от {sender}")

        nc.on_message_callback = on_message

        async def cmd_send(recipient, text):
            try:
                if recipient not in sessions:
                    info(f"Запрос ключей для {Colors.BOLD}{recipient}{Colors.RESET}...")
                    bundle = await nc.get_bundle(recipient)
                    if not bundle:
                        error(f"Пользователь {Colors.BOLD}{recipient}{Colors.RESET} не найден или нет ключей")
                        return
                    
                    info("Установка сессии X3DH...")
                    state, ek_pub, _ = SessionManager.initiate_session(
                        cm.ik_x25519_priv, cm.ik_x25519_pub, bundle, None
                    )
                    sessions[recipient] = state
                    success(f"Защищённая сессия с {recipient} установлена")
                    
                    ciphertext, header = SessionManager.encrypt_for_session(state, text.encode())
                    message_data = {
                        "type": "prekey",
                        "ik_a_pub": base64.b64encode(cm.ik_x25519_pub).decode(),
                        "ek_a_pub": base64.b64encode(ek_pub).decode(),
                        "opk_id": None,
                        "ciphertext": base64.b64encode(ciphertext).decode(),
                        "header": header
                    }
                else:
                    state = sessions[recipient]
                    ciphertext, header = SessionManager.encrypt_for_session(state, text.encode())
                    message_data = {
                        "type": "message",
                        "ciphertext": base64.b64encode(ciphertext).decode(),
                        "header": header
                    }
                
                await nc.send_message(recipient, message_data)
                outgoing_msg(recipient, text)
            except Exception as e:
                error(f"Ошибка отправки: {e}")

        if args.command == "register":
            bundle = cm.export_bundle()
            ok = await nc.register(cm.username, password, bundle)
            if ok:
                success(f"Пользователь {Colors.BOLD}{cm.username}{Colors.RESET} зарегистрирован")
                info("Ключи загружены на сервер (KDS)")
            else:
                error("Ошибка регистрации")
                
        elif args.command == "send":
            await cmd_send(args.recipient, args.message)
            await asyncio.sleep(1)
            
        elif args.command == "listen":
            header(f"ОЖИДАНИЕ СООБЩЕНИЙ")
            info(f"Пользователь: {Colors.BOLD}{cm.username}{Colors.RESET}")
            print(f"  {Colors.DIM}Ctrl+C для выхода{Colors.RESET}\n")
            try:
                await asyncio.Event().wait()
            except KeyboardInterrupt:
                print()
                info("Выход...")
                
        elif args.command == "chat":
            header(f"ЗАЩИЩЁННЫЙ ЧАТ")
            print(f"  {Colors.BOLD}Вы:{Colors.RESET}      {Colors.CYAN}{cm.username}{Colors.RESET}")
            print(f"  {Colors.BOLD}Собеседник:{Colors.RESET} {Colors.MAGENTA}{args.recipient}{Colors.RESET}")
            print(f"  {Colors.DIM}Протокол: X3DH + Double Ratchet + AES-256-GCM{Colors.RESET}")
            print(f"  {Colors.DIM}Введите 'quit' для выхода{Colors.RESET}")
            print(f"{Colors.DIM}{'─'*50}{Colors.RESET}\n")
            
            try:
                while True:
                    text = await asyncio.get_event_loop().run_in_executor(
                        None, input, f"{Colors.CYAN}[Вы] > {Colors.RESET}"
                    )
                    if text.lower() == 'quit':
                        break
                    if text.strip():
                        await cmd_send(args.recipient, text.strip())
            except KeyboardInterrupt:
                print()
                info("Выход из чата...")
    except Exception as e:
        error(f"Критическая ошибка: {e}")
    finally:
        await nc.close()

async def main():
    parser = argparse.ArgumentParser(
        description=f"{Colors.BOLD}Защищённый E2EE чат{Colors.RESET}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.DIM}Примеры:{Colors.RESET}
  python client/cli.py register -u alice -p alice123
  python client/cli.py chat -u alice -p alice123 -r bob
  python client/cli.py send -u bob -p bob123 -r alice -m "Привет!"
        """
    )
    parser.add_argument("command", choices=["register", "send", "listen", "chat"])
    parser.add_argument("-u", "--user", dest="username")
    parser.add_argument("-p", "--password")
    parser.add_argument("-r", "--recipient")
    parser.add_argument("-m", "--message")
    args = parser.parse_args()

    if not args.username:
        args.username = input(f"{Colors.CYAN}Имя пользователя:{Colors.RESET} ").strip()

    cm = await init_client(args.username)
    await login_and_run(cm, args)

if __name__ == "__main__":
    asyncio.run(main())