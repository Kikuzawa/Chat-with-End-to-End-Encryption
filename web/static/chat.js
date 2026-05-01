/* SecureChat – клиентская логика через Socket.IO (не хранит пароль) */

var socket = io();

var state = {
    username: null,          // пароль НЕ хранится
    currentContact: null,
    contacts: {}             // username -> [{sender, text, direction}]
};

// ── Инициализация после загрузки DOM ─────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function () {

    // Вкладки Вход / Регистрация
    document.getElementById('tab-login').onclick = function () {
        setTab('login');
    };
    document.getElementById('tab-register').onclick = function () {
        setTab('register');
    };

    // Форма регистрации
    document.getElementById('register-form').onsubmit = function (e) {
        e.preventDefault();
        var username = document.getElementById('register-username').value.trim();
        var password = document.getElementById('register-password').value.trim();
        if (!username || !password) {
            showAuthError('Заполните все поля');
            return;
        }
        showAuthError('Регистрация...');
        socket.emit('register', { username: username, password: password });
        // Пароль не сохраняется в state
    };

    // Форма входа
    document.getElementById('login-form').onsubmit = function (e) {
        e.preventDefault();
        var username = document.getElementById('login-username').value.trim();
        var password = document.getElementById('login-password').value.trim();
        if (!username || !password) {
            showAuthError('Заполните все поля');
            return;
        }
        showAuthError('Вход...');
        socket.emit('login', { username: username, password: password });
        // Пароль не сохраняется в state
    };

    // Отправка сообщения
    document.getElementById('send-button').onclick = sendMessage;
    document.getElementById('message-input').onkeypress = function (e) {
        if (e.key === 'Enter') { e.preventDefault(); sendMessage(); }
    };

    // Добавить контакт
    document.getElementById('add-contact-btn').onclick = function () {
        var input = document.getElementById('contact-input');
        var name = input.value.trim();
        if (name && !(name in state.contacts)) {
            state.contacts[name] = [];
            renderContacts();
            selectContact(name);
        }
        input.value = '';
    };

    // Выход
    document.getElementById('logout-btn').onclick = function () {
        if (state.username) {
            socket.emit('logout', { username: state.username });
        }
        document.getElementById('auth-screen').className = 'screen active';
        document.getElementById('chat-screen').className = 'screen';
        state.username = null;
        state.currentContact = null;
        state.contacts = {};
        clearMessages();
        document.getElementById('contacts-list').innerHTML = '';
        setTab('login');
    };
});

// ── Socket.IO события ─────────────────────────────────────────────────────────

socket.on('register_response', function (data) {
    if (data.status === 'ok') {
        state.username = data.username;
        showChat();
    } else {
        showAuthError(data.error || 'Ошибка регистрации');
    }
});

socket.on('login_response', function (data) {
    if (data.status === 'ok') {
        state.username = data.username;
        showChat();
    } else {
        showAuthError(data.error || 'Неверные учётные данные');
    }
});

// Входящее (расшифрованное на сервере Flask) сообщение
socket.on('message', function (data) {
    var sender = data.sender;
    var text   = data.text || '[Ошибка расшифровки]';
    var isErr  = !!data.error;

    if (!(sender in state.contacts)) {
        state.contacts[sender] = [];
        renderContacts();
    }
    state.contacts[sender].push({ sender: sender, text: text, direction: 'received' });

    if (state.currentContact === sender) {
        appendMessage(text, 'received', isErr);
    }
});

socket.on('message_sent', function (data) {
    // UI уже обновлён в sendMessage()
});

socket.on('error', function (data) {
    console.error('[SecureChat error]', data.message);
});

socket.on('disconnect', function () {
    console.warn('Socket.IO disconnected');
});

// ── Логика UI ─────────────────────────────────────────────────────────────────

function setTab(tab) {
    if (tab === 'login') {
        document.getElementById('tab-login').className     = 'tab active';
        document.getElementById('tab-register').className  = 'tab';
        document.getElementById('login-form').className    = 'auth-form active';
        document.getElementById('register-form').className = 'auth-form';
    } else {
        document.getElementById('tab-register').className  = 'tab active';
        document.getElementById('tab-login').className     = 'tab';
        document.getElementById('register-form').className = 'auth-form active';
        document.getElementById('login-form').className    = 'auth-form';
    }
    showAuthError('');
}

function showAuthError(msg) {
    document.getElementById('auth-error').textContent = msg;
}

function showChat() {
    document.getElementById('auth-screen').className = 'screen';
    document.getElementById('chat-screen').className = 'screen active';
    document.getElementById('current-username').textContent = state.username;
    document.getElementById('user-avatar').textContent = state.username[0].toUpperCase();
}

function sendMessage() {
    var text = document.getElementById('message-input').value.trim();
    if (!text || !state.currentContact || !state.username) { return; }

    // Отправляем через Socket.IO → webapp.py → (шифрование) → MessageServer
    socket.emit('send_message', {
        username:  state.username,
        recipient: state.currentContact,
        text:      text
    });

    if (!(state.currentContact in state.contacts)) {
        state.contacts[state.currentContact] = [];
    }
    state.contacts[state.currentContact].push({
        sender: state.username, text: text, direction: 'sent'
    });
    appendMessage(text, 'sent', false);
    document.getElementById('message-input').value = '';
}

function appendMessage(text, direction, isError) {
    var welcome = document.querySelector('.welcome-message');
    if (welcome) { welcome.remove(); }

    var div  = document.createElement('div');
    div.className = 'message ' + direction + (isError ? ' error-msg' : '');

    var span = document.createElement('div');
    span.className   = 'msg-text';
    span.textContent = text;   // textContent автоматически экранирует HTML (XSS-защита)
    div.appendChild(span);

    var container = document.getElementById('messages-container');
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function clearMessages() {
    var container = document.getElementById('messages-container');
    container.innerHTML =
        '<div class="welcome-message">' +
        '<div class="welcome-icon">&#128274;</div>' +
        '<h3>Защищённый чат</h3>' +
        '<p>Все сообщения шифруются end-to-end</p>' +
        '<p class="protocol-info">X3DH + Double Ratchet + AES-256-GCM</p>' +
        '</div>';
}

function renderContacts() {
    var html = '';
    for (var name in state.contacts) {
        var active = (name === state.currentContact) ? ' active' : '';
        // Безопасное формирование onclick: имя пользователя через data-атрибут
        html += '<div class="contact-item' + active + '" data-name="' +
                escapeAttr(name) + '">' +
                '<span>' + escapeHtml(name[0] || '?').toUpperCase() + '</span> ' +
                escapeHtml(name) + '</div>';
    }
    var list = document.getElementById('contacts-list');
    list.innerHTML = html;
    // Назначаем обработчики через addEventListener, не через innerHTML onclick
    var items = list.querySelectorAll('.contact-item');
    for (var i = 0; i < items.length; i++) {
        items[i].addEventListener('click', (function (el) {
            return function () { selectContact(el.dataset.name); };
        })(items[i]));
    }
}

function selectContact(name) {
    state.currentContact = name;
    document.getElementById('chat-partner').textContent = name;
    document.getElementById('message-input').disabled  = false;
    document.getElementById('send-button').disabled    = false;
    renderContacts();

    // Показываем историю этого контакта
    var container = document.getElementById('messages-container');
    container.innerHTML = '';
    var msgs = state.contacts[name] || [];
    for (var i = 0; i < msgs.length; i++) {
        appendMessage(msgs[i].text, msgs[i].direction, false);
    }
    if (!msgs.length) { clearMessages(); }
}

// ── Вспомогательные функции ───────────────────────────────────────────────────

function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function escapeAttr(s) {
    return String(s).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
