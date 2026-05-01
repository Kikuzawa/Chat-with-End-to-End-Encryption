#!/usr/bin/env python3
"""
CLI клиент защищённого чата (стр. 36).
Использование:
  python client/cli.py register -u alice -p alice123
  python client/cli.py send -u alice -p alice123 -r bob -m "Привет!"
  python client/cli.py listen -u bob -p bob123
  python client/cli.py chat -u alice -p alice123 -r bob
"""
import asyncio
import argparse
import json
import sys
import os
from pathlib import Path

# Добавляем корень проекта в PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from client.networkclient import NetworkClient
from crypto.keymanager import KeyManager
from crypto.sessionmanager import SessionManager, RatchetState
from crypto.messagecrypto import MessageCrypto
from crypto.contactverifier import ContactVerifier
import base64

# Используем localhost если сервер запущен локально, иначе message-server (из docker)
SERVER_URL = os.getenv("SERVER_URL", "ws://localhost:8000/ws")

# Глобальное хранилище сессий: contact -> RatchetState
sessions = {}

async def init_client(username=None):
    """Инициализация клиента: загрузка ключей или генерация."""
    key_path = Path.home() / ".secure-chat" / f"{username}_keys.json" if username else Path.home() / ".secure-chat" / "keys.json"
    
    # Создаем директорию если её нет
    key_path.parent.mkdir(parents=True, exist_ok=True)
    
    keyman = KeyManager(str(key_path))
    
    if key_path.exists():
        try:
            keyman = KeyManager.load_keys(str(key_path))
            print(f"✅ Загружены ключи пользователя {keyman.username}")
            print(f"🔑 Отпечаток IK: {ContactVerifier.fingerprint(keyman.ik_x25519_pub)}")
            return keyman
        except Exception as e:
            print(f"⚠️  Ошибка загрузки ключей: {e}")
            print("Создаём новые ключи...")
    
    # Генерируем новые ключи
    keyman.generate_identity_key()
    keyman.generate_spk()
    keyman.generate_opks(10)  # 10 ключей для тестирования
    
    if not username:
        username = input("Введите имя пользователя (новый): ").strip()
        if not username:
            print("❌ Имя пользователя не может быть пустым")
            sys.exit(1)
    
    keyman.username = username
    keyman.save_keys(username)
    print(f"✅ Созданы ключи для {username}.")
    print(f"🔑 Отпечаток IK: {ContactVerifier.fingerprint(keyman.ik_x25519_pub)}")
    return keyman

async def get_password(args, prompt="Пароль: "):
    """Получить пароль из аргументов или запросить."""
    if args.password:
        return args.password
    return input(prompt).strip()

async def register(cm: KeyManager, args):
    """Регистрация пользователя на сервере."""
    nc = NetworkClient(SERVER_URL)
    try:
        await nc.connect()
        password = await get_password(args)
        if not password:
            print("❌ Пароль не может быть пустым")
            return
        
        bundle = cm.export_bundle()
        ok = await nc.register(cm.username, password, bundle)
        if ok:
            print(f"✅ Регистрация пользователя {cm.username} успешна.")
        else:
            print("❌ Ошибка регистрации.")
    except Exception as e:
        print(f"❌ Ошибка: {e}")
    finally:
        await nc.close()

async def login_and_run(cm: KeyManager, args):
    """Вход и выполнение команд."""
    nc = NetworkClient(SERVER_URL)
    try:
        await nc.connect()
        password = await get_password(args)
        
        # Если это не регистрация, пробуем войти
        if args.command != "register":
            ok = await nc.login(cm.username, password)
            if not ok:
                print("❌ Ошибка входа. Проверьте имя пользователя и пароль.")
                return
            print(f"✅ Вход выполнен как {cm.username}.")

        # Обработчик входящих сообщений
               # Обработчик входящих сообщений
        async def on_message(sender, data):
            print(f"\n📩 [Входящее от {sender}]:", end=" ")
            try:
                msg_type = data.get("type", "message")
                
                if sender not in sessions:
                    if msg_type == "prekey":
                        print("(X3DH установка сессии)", end=" ")
                        init_ik_pub = base64.b64decode(data["ik_a_pub"])
                        init_ek_pub = base64.b64decode(data["ek_a_pub"])
                        opk_id = None  # Игнорируем OPK
                        
                        # Ищем использованный OPK
                        opk_priv_dict = {}
                        if opk_id is not None and cm.opks:
                            if opk_id < len(cm.opks):
                                opk_priv_dict[opk_id] = cm.opks[opk_id][0]
                                print(f"[OPK #{opk_id}]", end=" ")
                            else:
                                # OPK не найден - пробуем без него
                                print(f"[OPK #{opk_id} не найден]", end=" ")
                        
                        # Принимаем сессию
                        state = SessionManager.receive_session(
                            cm.ik_x25519_priv,
                            cm.ik_x25519_pub,
                            cm.spk_priv,
                            cm.spk_pub,
                            {},  # Пустой словарь OPK
                            init_ik_pub,
                            init_ek_pub,
                            None  # Без OPK
                        )
                        sessions[sender] = state
                        
                        # Расшифровываем первое сообщение
                        ciphertext = base64.b64decode(data["ciphertext"])
                        header = data["header"]
                        plain = SessionManager.decrypt_from_session(state, ciphertext, header)
                        print("✅", plain.decode())
                    else:
                        print(f"❌ Ожидался prekey, получен {msg_type}")
                else:
                    # Обычное сообщение
                    state = sessions[sender]
                    ciphertext = base64.b64decode(data["ciphertext"])
                    header = data["header"]
                    plain = SessionManager.decrypt_from_session(state, ciphertext, header)
                    print("✅", plain.decode())
            except Exception as e:
                print(f"❌ Ошибка: {e}")
                import traceback
                traceback.print_exc()

        nc.on_message_callback = on_message

        # Функция отправки сообщения
        async def cmd_send(recipient, text):
            try:
                if recipient not in sessions:
                    print(f"🔍 Запрашиваю ключи для {recipient}...")
                    bundle = await nc.get_bundle(recipient)
                    if not bundle:
                        print(f"❌ Пользователь {recipient} не найден.")
                        return
                    
                    print(f"🔑 Устанавливаю сессию X3DH...")
                    # ВСЕГДА передаем None для OPK, так как Bob не знает какой OPK использован
                    opk_used_id = None
                    
                    state, ek_pub, _ = SessionManager.initiate_session(
                        cm.ik_x25519_priv, cm.ik_x25519_pub, bundle, opk_used_id
                    )
                    sessions[recipient] = state
                    
                    ciphertext, header = SessionManager.encrypt_for_session(state, text.encode())
                    message_data = {
                        "type": "prekey",
                        "ik_a_pub": base64.b64encode(cm.ik_x25519_pub).decode(),
                        "ek_a_pub": base64.b64encode(ek_pub).decode(),
                        "opk_id": None,  # Не используем OPK
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
                print(f"✅ Отправлено: {text}")
            except Exception as e:
                print(f"❌ Ошибка отправки: {e}")
                traceback.print_exc()

        # Выполнение команды
        if args.command == "register":
            # Регистрация уже выполнена в main, здесь просто ждем
            bundle = cm.export_bundle()
            ok = await nc.register(cm.username, password, bundle)
            if ok:
                print(f"✅ Регистрация пользователя {cm.username} успешна.")
            else:
                print("❌ Ошибка регистрации.")
                
        elif args.command == "send":
            if not args.recipient:
                print("❌ Укажите получателя: -r username")
                return
            if not args.message:
                print("❌ Укажите сообщение: -m \"текст\"")
                return
            await cmd_send(args.recipient, args.message)
            await asyncio.sleep(2)
            
        elif args.command == "listen":
            print(f"👂 {cm.username} ожидает сообщений (Ctrl+C для выхода)...")
            try:
                await asyncio.Event().wait()
            except KeyboardInterrupt:
                print("\n👋 Выход...")
                
        elif args.command == "chat":
            if not args.recipient:
                print("❌ Укажите собеседника: -r username")
                return
            print(f"💬 Чат с {args.recipient}")
            print("Вводите сообщения (Ctrl+C для выхода, 'quit' для завершения):")
            try:
                while True:
                    text = await asyncio.get_event_loop().run_in_executor(
                        None, input, "Вы: "
                    )
                    if text.lower() == 'quit':
                        break
                    if text.strip():
                        await cmd_send(args.recipient, text.strip())
            except KeyboardInterrupt:
                print("\n👋 Выход из чата...")
    except Exception as e:
        print(f"❌ Ошибка: {e}")
    finally:
        await nc.close()

async def main():
    parser = argparse.ArgumentParser(
        description="🔐 Защищённый E2EE чат с сквозным шифрованием",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python client/cli.py register -u alice -p alice123
  python client/cli.py register -u bob -p bob123
  python client/cli.py listen -u alice -p alice123
  python client/cli.py send -u bob -p bob123 -r alice -m "Привет!"
  python client/cli.py chat -u alice -p alice123 -r bob
        """
    )
    parser.add_argument("command", choices=["register", "send", "listen", "chat"],
                       help="Команда для выполнения")
    parser.add_argument("-u", "--user", "--username", dest="username",
                       help="Имя пользователя")
    parser.add_argument("-p", "--password", 
                       help="Пароль (если не указан, будет запрошен)")
    parser.add_argument("-r", "--recipient", 
                       help="Получатель сообщения")
    parser.add_argument("-m", "--message", 
                       help="Текст сообщения")
    
    args = parser.parse_args()

    # Проверка обязательных аргументов
    if not args.username:
        args.username = input("Имя пользователя: ").strip()
        if not args.username:
            print("❌ Имя пользователя обязательно")
            return

    if args.command in ("send", "chat") and not args.recipient:
        print("❌ Укажите получателя: -r username")
        return

    # Инициализация клиента с именем пользователя
    cm = await init_client(args.username)
    
    # Выполнение команды
    await login_and_run(cm, args)

if __name__ == "__main__":
    asyncio.run(main())