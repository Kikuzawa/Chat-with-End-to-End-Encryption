"""
API endpoints для интерактивной визуализации алгоритма E2EE чата.
Парсит логи из файлов и возвращает их по шагам (step_id).
"""
import os
import re
import json
from pathlib import Path

LOG_DIR = os.getenv("LOG_DIR", "/app/logs")

# Описания шагов (step_id → информация)
STEP_INFO = {
    "1.0": {
        "title": "НАЧАЛО",
        "description": "Инициализация приложения"
    },
    "1.1": {
        "title": "Инициализация клиента",
        "description": "Загрузка Web UI или CLI интерфейса"
    },
    "1.2": {
        "title": "Подключение к серверу",
        "description": "Установка WebSocket соединения с MessageServer"
    },
    "1.3": {
        "title": "Отображение экрана",
        "description": "Показ формы входа или регистрации"
    },
    "1.4": {
        "title": "Проверка статуса пользователя",
        "description": "Решение: новый пользователь или существующий?"
    },
    "2.0": {
        "title": "Вход",
        "description": "Процесс аутентификации существующего пользователя"
    },
    "2.1": {
        "title": "Ввод учётных данных",
        "description": "Пользователь вводит username и password"
    },
    "2.2": {
        "title": "Отправка запроса входа",
        "description": "WebSocket сообщение type=login на MessageServer"
    },
    "2.3": {
        "title": "Проверка учётных данных",
        "description": "Сервер проверяет хеш пароля (PBKDF2-SHA256)"
    },
    "2.4": {
        "title": "Решение: вход удачен?",
        "description": "Проверка соответствия хеша пароля"
    },
    "2.5": {
        "title": "Ошибка входа",
        "description": "Неверные учётные данные, возврат к шагу 2.1"
    },
    "2.6": {
        "title": "Загрузка данных пользователя",
        "description": "Получение списка контактов и сессий из Redis"
    },
    "3.0": {
        "title": "Регистрация",
        "description": "Процесс регистрации нового пользователя"
    },
    "3.1": {
        "title": "Ввод данных регистрации",
        "description": "Пользователь вводит username и password"
    },
    "3.2": {
        "title": "Генерация ключей клиента",
        "description": "Создание IK (Identity Key), SPK (Signed PreKey), OPK пула (One-Time PreKeys)"
    },
    "3.3": {
        "title": "Загрузка публичного бандла в KDS",
        "description": "HTTPS запрос к Key Distribution Server с публичными ключами"
    },
    "3.4": {
        "title": "Регистрация пользователя на сервере",
        "description": "WebSocket сообщение type=register на MessageServer"
    },
    "3.5": {
        "title": "Сохранение ключей на устройстве",
        "description": "Локальное сохранение приватных ключей в защищённом хранилище"
    },
    "4.0": {
        "title": "Отображение интерфейса чата",
        "description": "Показ списка контактов, истории сообщений"
    },
    "5.0": {
        "title": "Выбор действия",
        "description": "Пользователь выбирает: отправить сообщение или выйти"
    },
    "5.1": {
        "title": "Решение: отправить сообщение?",
        "description": "Проверка выбора действия"
    },
    "5.2": {
        "title": "Выбор получателя и ввод текста",
        "description": "Пользователь выбирает получателя и вводит сообщение"
    },
    "5.7": {
        "title": "Ожидание входящих сообщений",
        "description": "Фоновый поток слушает сообщения от сервера"
    },
    "6.0": {
        "title": "Получение сообщения от сервера",
        "description": "Сервер отправляет зашифрованное сообщение"
    },
    "6.1": {
        "title": "Проверка отправителя",
        "description": "Определение, есть ли уже сессия с этим отправителем"
    },
    "6.2": {
        "title": "Решение: сессия существует?",
        "description": "Выбор между инициализацией X3DH или расшифровкой Double Ratchet"
    },
    "6.3": {
        "title": "Расшифровка (Double Ratchet)",
        "description": "Использование существующей сессии для расшифровки"
    },
    "6.4": {
        "title": "Отображение сообщения",
        "description": "Показ расшифрованного сообщения в интерфейсе"
    },
    "6.5": {
        "title": "Инициализация сессии (X3DH receive)",
        "description": "Первое сообщение: выполнение X3DH receive_session"
    },
    "6.6": {
        "title": "Расшифровка сообщения",
        "description": "Double Ratchet расшифровка после X3DH инициализации"
    },
    "7.0": {
        "title": "Решение: выйти?",
        "description": "Проверка: пользователь хочет завершить сеанс?"
    },
    "7.1": {
        "title": "Выход пользователя",
        "description": "Инициирование процесса выхода"
    },
    "7.2": {
        "title": "Закрытие соединения",
        "description": "Закрытие WebSocket соединения (WSS Close)"
    },
    "7.3": {
        "title": "Очистка сессионных данных",
        "description": "Удаление сессий, токенов и локального состояния"
    },
    "7.4": {
        "title": "КОНЕЦ",
        "description": "Завершение приложения"
    }
}

def get_step_logs(step_id: str) -> dict:
    """Получает логи для конкретного шага."""
    info = STEP_INFO.get(step_id, {
        "title": "Неизвестный шаг",
        "description": ""
    })

    # Маппинг step_id на теги в логах
    step_to_log_tags = {
        "1.0": [],
        "1.1": ["[WEBAPP/INIT]"],
        "1.2": ["[WEBAPP/LOGIN]", "[WEBAPP/REGISTER]"],
        "3.2": ["[KEYMANAGER/GEN/IK]", "[KEYMANAGER/GEN/SPK]", "[KEYMANAGER/GEN/OPK]"],
        "3.3": ["[SERVER/REGISTER]", "[SERVER/UPDATE_BUNDLE]"],
        "3.5": ["[KEYMANAGER/SAVE]"],
        "2.1": ["[WEBAPP/LOGIN]"],
        "2.2": ["[SERVER/LOGIN]"],
        "2.3": ["[SERVER/LOGIN]"],
        "2.6": ["[SERVER/QUEUE]"],
        "5.2": ["[WEBAPP/SEND]"],
        "6.0": ["[SERVER/SEND]"],
        "6.1": ["[WEBAPP/RECV]"],
        "6.3": ["[CRYPTO/RATCHET/DEC]"],
        "6.5": ["[CRYPTO/X3DH/RECEIVE]"],
        "6.6": ["[CRYPTO/RATCHET/DEC]"],
    }

    logs = _extract_logs(step_to_log_tags.get(step_id, []))
    keys = _extract_keys_for_step(step_id, logs)

    return {
        "step_id": step_id,
        "title": info["title"],
        "description": info["description"],
        "logs": logs,
        "keys": keys,
        "duration_ms": _estimate_duration(logs)
    }

def _extract_logs(tags: list) -> str:
    """Извлекает логи из файлов по тегам."""
    if not tags:
        return ""

    logs = []
    log_files = [
        os.path.join(LOG_DIR, "crypto.log"),
        os.path.join(LOG_DIR, "webapp.log"),
        os.path.join(LOG_DIR, "server.log"),
        os.path.join(LOG_DIR, "keymanager.log"),
    ]

    for log_file in log_files:
        if not os.path.exists(log_file):
            continue
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    for tag in tags:
                        if tag in line:
                            logs.append(line.strip())
                            break
        except Exception:
            pass

    # Берём последние 50 строк (последний запуск)
    return '\n'.join(logs[-50:])

def _extract_keys_for_step(step_id: str, logs: str) -> dict:
    """Извлекает ключи и компоненты из логов для конкретного шага."""
    keys = {}

    if step_id == "3.2":
        # Генерация ключей
        ik_match = re.search(r"IK_x25519_pub\s*=\s*([a-f0-9\.]+)", logs)
        if ik_match:
            keys["IK_x25519_pub"] = ik_match.group(1)
        spk_match = re.search(r"SPK_pub\s*=\s*([a-f0-9\.]+)", logs)
        if spk_match:
            keys["SPK_pub"] = spk_match.group(1)
        opk_match = re.search(r"OPK count\s*=\s*(\d+)", logs)
        if opk_match:
            keys["OPK_count"] = int(opk_match.group(1))

    elif step_id == "3.5":
        # Сохранение ключей
        ik_match = re.search(r"IK_x25519_pub\s*=\s*([a-f0-9\.]+)", logs)
        if ik_match:
            keys["IK_x25519_pub (saved)"] = ik_match.group(1)
        spk_match = re.search(r"SPK_pub\s*=\s*([a-f0-9\.]+)", logs)
        if spk_match:
            keys["SPK_pub (saved)"] = spk_match.group(1)

    elif step_id in ["6.3", "6.6"]:
        # Расшифровка
        ct_match = re.search(r"ct=(\d+)\s*байт", logs)
        if ct_match:
            keys["Ciphertext_size"] = int(ct_match.group(1))
        hdr_match = re.search(r"hdr=([a-zA-Z0-9]+)", logs)
        if hdr_match:
            keys["Header"] = hdr_match.group(1)

    elif step_id == "6.5":
        # X3DH receive
        ik_a_match = re.search(r"IK_A_pub\s*=\s*([a-f0-9\.]+)", logs)
        if ik_a_match:
            keys["IK_A_pub"] = ik_a_match.group(1)
        ek_a_match = re.search(r"EK_A_pub\s*=\s*([a-f0-9\.]+)", logs)
        if ek_a_match:
            keys["EK_A_pub"] = ek_a_match.group(1)

    return keys

def _estimate_duration(logs: str) -> int:
    """Оценивает длительность операции (в миллисекундах)."""
    lines = logs.split('\n')
    if len(lines) < 2:
        return 0

    # Извлекаем времена из логов
    times = []
    for line in lines:
        match = re.match(r"(\d{2}):(\d{2}):(\d{2})\.(\d{3})", line)
        if match:
            h, m, s, ms = map(int, match.groups())
            total_ms = h * 3600000 + m * 60000 + s * 1000 + ms
            times.append(total_ms)

    if len(times) >= 2:
        return times[-1] - times[0]
    return 0
