console.log('=== CHAT.JS v3 LOADED ===');

var state = {
    username: null,
    password: null,  // СОХРАНЯЕМ ПАРОЛЬ
    currentContact: null,
    contacts: []
};

var messageWs = null;

document.addEventListener('DOMContentLoaded', function() {
    
    // Вкладки
    document.getElementById('tab-login').onclick = function() {
        document.getElementById('tab-login').className = 'tab active';
        document.getElementById('tab-register').className = 'tab';
        document.getElementById('login-form').className = 'auth-form active';
        document.getElementById('register-form').className = 'auth-form';
        document.getElementById('auth-error').textContent = '';
    };
    
    document.getElementById('tab-register').onclick = function() {
        document.getElementById('tab-register').className = 'tab active';
        document.getElementById('tab-login').className = 'tab';
        document.getElementById('register-form').className = 'auth-form active';
        document.getElementById('login-form').className = 'auth-form';
        document.getElementById('auth-error').textContent = '';
    };
    
    // РЕГИСТРАЦИЯ
    document.getElementById('register-form').onsubmit = function(e) {
        e.preventDefault();
        var username = document.getElementById('register-username').value.trim();
        var password = document.getElementById('register-password').value.trim();
        
        if (!username || !password) {
            document.getElementById('auth-error').textContent = 'Заполните все поля';
            return;
        }
        
        console.log('РЕГИСТРАЦИЯ:', username, 'пароль:', password);
        document.getElementById('auth-error').textContent = 'Регистрация...';
        
        var ws = new WebSocket('ws://localhost:8000/ws');
        
        ws.onopen = function() {
            console.log('WebSocket открыт для регистрации');
            ws.send(JSON.stringify({
                type: 'register',
                username: username,
                password: password
            }));
        };
        
        ws.onmessage = function(event) {
            console.log('Ответ регистрации:', event.data);
            var data = JSON.parse(event.data);
            
            if (data.status === 'ok') {
                console.log('Регистрация успешна!');
                state.username = username;
                state.password = password;  // СОХРАНЯЕМ ПАРОЛЬ
                ws.close();
                showChat();
            } else if (data.message === 'User already exists') {
                // Пользователь уже есть - просто логинимся
                console.log('Пользователь существует, логинимся...');
                state.username = username;
                state.password = password;
                ws.close();
                showChat();
            } else {
                document.getElementById('auth-error').textContent = data.message || 'Ошибка';
                ws.close();
            }
        };
        
        ws.onerror = function() {
            document.getElementById('auth-error').textContent = 'Сервер недоступен!';
        };
    };
    
    // ЛОГИН
    document.getElementById('login-form').onsubmit = function(e) {
        e.preventDefault();
        var username = document.getElementById('login-username').value.trim();
        var password = document.getElementById('login-password').value.trim();
        
        if (!username || !password) {
            document.getElementById('auth-error').textContent = 'Заполните все поля';
            return;
        }
        
        console.log('ЛОГИН:', username);
        document.getElementById('auth-error').textContent = 'Вход...';
        
        // Просто сохраняем и показываем чат
        state.username = username;
        state.password = password;
        showChat();
    };
    
    // Отправка сообщения
    document.getElementById('send-button').onclick = sendMessage;
    
    // Enter
    document.getElementById('message-input').onkeypress = function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            sendMessage();
        }
    };
    
    // Добавить контакт
    document.getElementById('add-contact-btn').onclick = function() {
        var input = document.getElementById('contact-input');
        var name = input.value.trim();
        if (name) {
            state.contacts.push(name);
            renderContacts();
            selectContact(name);
        }
        input.value = '';
    };
    
    // Выход
    document.getElementById('logout-btn').onclick = function() {
        if (messageWs) messageWs.close();
        document.getElementById('auth-screen').className = 'screen active';
        document.getElementById('chat-screen').className = 'screen';
        state.username = null;
        state.password = null;
        state.currentContact = null;
        state.contacts = [];
    };
});

function showChat() {
    console.log('Показываем чат для', state.username);
    document.getElementById('auth-screen').className = 'screen';
    document.getElementById('chat-screen').className = 'screen active';
    document.getElementById('current-username').textContent = state.username;
    document.getElementById('user-avatar').textContent = state.username[0].toUpperCase();
    connectToMessageServer();
}

function connectToMessageServer() {
    console.log('Подключение к MessageServer как', state.username);
    
    messageWs = new WebSocket('ws://localhost:8000/ws');
    
    messageWs.onopen = function() {
        console.log('WebSocket открыт, логинимся с паролем:', state.password);
        // ИСПОЛЬЗУЕМ СОХРАНЕННЫЙ ПАРОЛЬ
        messageWs.send(JSON.stringify({
            type: 'login',
            username: state.username,
            password: state.password
        }));
    };
    
    messageWs.onmessage = function(event) {
        var msg = JSON.parse(event.data);
        console.log('Получено:', msg.type, msg);
        
        if (msg.type === 'login' && msg.status === 'ok') {
            console.log('Логин на MessageServer успешен!');
        }
        
        if (msg.type === 'message') {
            var sender = msg.sender;
            var text = msg.data.text || '[encrypted]';
            console.log('СООБЩЕНИЕ от', sender, ':', text);
            
            // Автоматически добавляем контакт
            if (state.contacts.indexOf(sender) === -1) {
                state.contacts.push(sender);
                renderContacts();
            }
            
            // Автоматически открываем чат
            if (!state.currentContact || state.currentContact !== sender) {
                selectContact(sender);
            }
            
            addMessage(sender, text, 'received');
        }
    };
    
    messageWs.onclose = function() {
        console.log('WebSocket закрыт');
    };
    
    messageWs.onerror = function(err) {
        console.log('WebSocket ошибка:', err);
    };
}

function sendMessage() {
    var text = document.getElementById('message-input').value.trim();
    if (!text || !state.currentContact || !messageWs) {
        console.log('Не могу отправить:', !text ? 'нет текста' : !state.currentContact ? 'нет контакта' : 'нет WebSocket');
        return;
    }
    
    console.log('Отправка:', text, '->', state.currentContact);
    
    messageWs.send(JSON.stringify({
        type: 'send',
        recipient: state.currentContact,
        message: {
            type: 'message',
            text: text
        }
    }));
    
    addMessage(state.username, text, 'sent');
    document.getElementById('message-input').value = '';
}

function addMessage(sender, text, direction) {
    var welcome = document.querySelector('.welcome-message');
    if (welcome) welcome.remove();
    
    var div = document.createElement('div');
    div.className = 'message ' + direction;
    div.innerHTML = '<div class="msg-text">' + text + '</div>';
    
    var container = document.getElementById('messages-container');
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function renderContacts() {
    var html = '';
    for (var i = 0; i < state.contacts.length; i++) {
        var c = state.contacts[i];
        var active = c === state.currentContact ? ' active' : '';
        html += '<div class="contact-item' + active + '" onclick="selectContact(\'' + c + '\')">' +
            '<span>' + c[0].toUpperCase() + '</span> ' + c +
        '</div>';
    }
    document.getElementById('contacts-list').innerHTML = html;
}

function selectContact(username) {
    state.currentContact = username;
    document.getElementById('chat-partner').textContent = username;
    document.getElementById('message-input').disabled = false;
    document.getElementById('send-button').disabled = false;
    renderContacts();
}

console.log('=== CHAT.JS ГОТОВ ===');