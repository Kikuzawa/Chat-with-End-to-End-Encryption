/* SecureChat – клиентская логика через Socket.IO */

var socket = io();

var state = {
    username:       null,
    currentContact: null,
    contacts:       {},    // username -> [{text, direction}]
    _pendingCreds:  null,  // временно при логине/регистрации
};

var AVATAR_GRADIENTS = [
    'linear-gradient(135deg,#3b82f6,#60a5fa)',
    'linear-gradient(135deg,#10b981,#34d399)',
    'linear-gradient(135deg,#f59e0b,#fbbf24)',
    'linear-gradient(135deg,#8b5cf6,#a78bfa)',
    'linear-gradient(135deg,#ef4444,#f87171)',
    'linear-gradient(135deg,#ec4899,#f472b6)',
];

function avatarGradient(name) {
    var h = 0;
    for (var i = 0; i < name.length; i++) {
        h = (h * 31 + name.charCodeAt(i)) % AVATAR_GRADIENTS.length;
    }
    return AVATAR_GRADIENTS[h];
}

// ── Инициализация после загрузки DOM ─────────────────────────────────────────

window.addEventListener('load', function () {
    // Скрываем loader и показываем экран авторизации
    var loader = document.getElementById('loader');
    if (loader) {
        loader.classList.add('hidden');
        setTimeout(function () { loader.style.display = 'none'; }, 450);
    }

    // Авто-вход из localStorage
    var saved = localStorage.getItem('securechat_creds');
    if (saved) {
        try {
            var creds = JSON.parse(saved);
            if (creds.username && creds.password) {
                state._pendingCreds = creds;
                document.getElementById('auth-error').textContent = 'Восстановление сессии…';
                document.getElementById('auth-screen').classList.add('active');
                socket.emit('login', creds);
                return;
            }
        } catch (_) {
            localStorage.removeItem('securechat_creds');
        }
    }
    document.getElementById('auth-screen').classList.add('active');
});

document.addEventListener('DOMContentLoaded', function () {

    // Вкладки Вход / Регистрация
    document.getElementById('tab-login').onclick = function () { setTab('login'); };
    document.getElementById('tab-register').onclick = function () { setTab('register'); };

    // Форма регистрации
    document.getElementById('register-form').onsubmit = function (e) {
        e.preventDefault();
        var username = document.getElementById('register-username').value.trim();
        var password = document.getElementById('register-password').value.trim();
        if (!username || !password) { showAuthError('Заполните все поля'); return; }
        state._pendingCreds = { username: username, password: password };
        showAuthError('Регистрация…');
        socket.emit('register', { username: username, password: password });
    };

    // Форма входа
    document.getElementById('login-form').onsubmit = function (e) {
        e.preventDefault();
        var username = document.getElementById('login-username').value.trim();
        var password = document.getElementById('login-password').value.trim();
        if (!username || !password) { showAuthError('Заполните все поля'); return; }
        state._pendingCreds = { username: username, password: password };
        showAuthError('Вход…');
        socket.emit('login', { username: username, password: password });
    };

    // Отправка сообщения
    document.getElementById('send-button').onclick = sendMessage;
    document.getElementById('message-input').onkeydown = function (e) {
        if (e.key === 'Enter') { e.preventDefault(); sendMessage(); }
    };

    // Добавить контакт
    document.getElementById('add-contact-btn').onclick = addContactFromInput;
    document.getElementById('contact-input').onkeydown = function (e) {
        if (e.key === 'Enter') addContactFromInput();
    };

    // Выход
    document.getElementById('logout-btn').onclick = function () {
        localStorage.removeItem('securechat_creds');
        if (state.username) {
            socket.emit('logout', { username: state.username });
        }
        document.getElementById('auth-screen').className = 'screen active';
        document.getElementById('chat-screen').className = 'screen';
        state.username       = null;
        state.currentContact = null;
        state.contacts       = {};
        clearMessages();
        document.getElementById('contacts-list').innerHTML = '';
        resetChatHeader();
        setTab('login');
    };

    // Открыть страницу логов
    document.getElementById('logs-btn').onclick = function () {
        window.open('/logs', '_blank');
    };
});

// ── Socket.IO события ─────────────────────────────────────────────────────────

socket.on('register_response', function (data) {
    if (data.status === 'ok') {
        state.username = data.username;
        if (state._pendingCreds) {
            localStorage.setItem('securechat_creds', JSON.stringify(state._pendingCreds));
            state._pendingCreds = null;
        }
        showChat();
    } else {
        state._pendingCreds = null;
        showAuthError(data.error || 'Ошибка регистрации');
    }
});

socket.on('login_response', function (data) {
    if (data.status === 'ok') {
        state.username = data.username;
        if (state._pendingCreds) {
            localStorage.setItem('securechat_creds', JSON.stringify(state._pendingCreds));
            state._pendingCreds = null;
        }
        showChat();
    } else {
        state._pendingCreds = null;
        localStorage.removeItem('securechat_creds');
        showAuthError(data.error || 'Неверные учётные данные');
    }
});

// Входящее (расшифрованное на webapp) сообщение
socket.on('message', function (data) {
    var sender = data.sender;
    var text   = data.text || '[Ошибка расшифровки]';
    var isErr  = !!data.error;

    if (!(sender in state.contacts)) {
        state.contacts[sender] = [];
        renderContacts();
    }
    state.contacts[sender].push({ text: text, direction: 'received' });

    if (state.currentContact === sender) {
        appendMessage(text, 'received', isErr);
    }
});

socket.on('message_sent', function () { /* UI обновлён в sendMessage() */ });

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

    var av = document.getElementById('user-avatar');
    av.textContent = state.username[0].toUpperCase();
    av.style.background = avatarGradient(state.username);

    document.getElementById('current-username').textContent = state.username;
}

function sendMessage() {
    var text = document.getElementById('message-input').value.trim();
    if (!text || !state.currentContact || !state.username) { return; }

    socket.emit('send_message', {
        username:  state.username,
        recipient: state.currentContact,
        text:      text,
    });

    if (!(state.currentContact in state.contacts)) {
        state.contacts[state.currentContact] = [];
    }
    state.contacts[state.currentContact].push({ text: text, direction: 'sent' });
    appendMessage(text, 'sent', false);
    document.getElementById('message-input').value = '';
}

function addContactFromInput() {
    var input = document.getElementById('contact-input');
    var name  = input.value.trim();
    if (name && !(name in state.contacts)) {
        state.contacts[name] = [];
        renderContacts();
        selectContact(name);
    } else if (name && name in state.contacts) {
        selectContact(name);
    }
    input.value = '';
}

function appendMessage(text, direction, isError) {
    var welcome = document.querySelector('.welcome-message');
    if (welcome) { welcome.remove(); }

    var time = new Date().toLocaleTimeString('ru', { hour: '2-digit', minute: '2-digit' });
    var check = direction === 'sent' ? ' ✓✓' : '';

    var div = document.createElement('div');
    div.className = 'message ' + direction + (isError ? ' error-msg' : '');

    var bubble = document.createElement('div');
    bubble.className = 'msg-bubble';

    var msgText = document.createElement('div');
    msgText.className   = 'msg-text';
    msgText.textContent = text;  // textContent экранирует HTML (XSS-защита)

    var msgMeta = document.createElement('div');
    msgMeta.className = 'msg-meta';
    msgMeta.textContent = time + check;

    bubble.appendChild(msgText);
    bubble.appendChild(msgMeta);
    div.appendChild(bubble);

    var container = document.getElementById('messages-container');
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function clearMessages() {
    document.getElementById('messages-container').innerHTML =
        '<div class="welcome-message">' +
        '<div class="welcome-icon">🔐</div>' +
        '<h3>Защищённый чат</h3>' +
        '<p>Все сообщения шифруются end-to-end</p>' +
        '<div class="welcome-badges">' +
        '<span class="badge-mono">X3DH</span>' +
        '<span class="badge-mono">Double Ratchet</span>' +
        '<span class="badge-mono">AES-256-GCM</span>' +
        '</div></div>';
}

function resetChatHeader() {
    document.getElementById('chat-header').innerHTML =
        '<div style="font-size:15px;color:var(--text-tertiary)">Выберите контакт</div>';
    document.getElementById('encrypt-hint').textContent = '';
    document.getElementById('message-input').disabled = true;
    document.getElementById('send-button').disabled   = true;
}

function renderContacts() {
    var html = '';
    for (var name in state.contacts) {
        var active = (name === state.currentContact) ? ' active' : '';
        var grad   = avatarGradient(name);
        html +=
            '<div class="contact-item' + active + '" data-name="' + escapeAttr(name) + '">' +
            '<div class="contact-avatar" style="background:' + grad + '">' +
            escapeHtml(name[0].toUpperCase()) + '</div>' +
            '<div class="contact-info"><div class="contact-name">' +
            escapeHtml(name) + '</div></div>' +
            '<div class="contact-online-dot"></div>' +
            '</div>';
    }
    var list = document.getElementById('contacts-list');
    list.innerHTML = html;
    var items = list.querySelectorAll('.contact-item');
    for (var i = 0; i < items.length; i++) {
        items[i].addEventListener('click', (function (el) {
            return function () { selectContact(el.dataset.name); };
        })(items[i]));
    }
}

function selectContact(name) {
    state.currentContact = name;

    var grad = avatarGradient(name);
    document.getElementById('chat-header').innerHTML =
        '<div class="avatar lg" style="background:' + grad + '">' +
        escapeHtml(name[0].toUpperCase()) + '</div>' +
        '<div class="chat-header-info">' +
        '<div class="chat-partner-name">' + escapeHtml(name) + '</div>' +
        '<div class="chat-fingerprint">🔐 E2EE · X3DH + Double Ratchet</div>' +
        '</div>' +
        '<span class="badge-session">Сессия активна</span>';

    document.getElementById('message-input').disabled = false;
    document.getElementById('send-button').disabled   = false;
    document.getElementById('encrypt-hint').textContent = '🔒 AES-256-GCM encrypted';

    renderContacts();

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
        .replace(/&/g,  '&amp;')
        .replace(/</g,  '&lt;')
        .replace(/>/g,  '&gt;')
        .replace(/"/g,  '&quot;');
}

function escapeAttr(s) {
    return String(s).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
