const $ = id => document.getElementById(id);
let mode = 'login', session = null, pollTimer = null, busy = false;
let messageLimit = 4096, tls = false, generation = 0;
const encoder = new TextEncoder();

async function request(path, data) {
  const response = await fetch(path, {
    method: data === undefined ? 'GET' : 'POST',
    headers: data === undefined ? {} : {'Content-Type': 'application/json'},
    body: data === undefined ? undefined : JSON.stringify(data),
    credentials: 'same-origin', cache: 'no-store'
  });
  const result = await response.json();
  if (!response.ok) {
    const error = new Error(result.error || 'Something went wrong. Please try again.');
    error.status = response.status;
    throw error;
  }
  return result;
}

function setMode(next) {
  if (busy) return;
  mode = next;
  const register = mode === 'register';
  $('login-tab').setAttribute('aria-selected', String(!register));
  $('register-tab').setAttribute('aria-selected', String(register));
  $('auth-title').textContent = register ? 'Find your people.' : 'Welcome back.';
  $('auth-subtitle').textContent = register ? "One account. A seat at your team's table." : 'Your next conversation is waiting.';
  $('confirm-group').hidden = !register;
  $('confirm').required = register;
  $('room-group').hidden = register;
  $('password').autocomplete = register ? 'new-password' : 'current-password';
  $('auth-submit').replaceChildren(document.createTextNode(register ? 'Create my account' : 'Join the conversation'));
  const arrow = document.createElement('span'); arrow.textContent = '↗'; $('auth-submit').append(arrow);
  $('auth-notice').textContent = '';
}
$('login-tab').onclick = () => setMode('login');
$('register-tab').onclick = () => setMode('register');
for (const id of ['login-tab', 'register-tab']) {
  $(id).onkeydown = event => {
    if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {
      event.preventDefault(); setMode(mode === 'login' ? 'register' : 'login');
      $(mode === 'login' ? 'login-tab' : 'register-tab').focus();
    }
  };
}
$('show-password').onclick = () => {
  const show = $('password').type === 'password';
  $('password').type = show ? 'text' : 'password';
  $('show-password').textContent = show ? 'Hide' : 'Show';
  $('show-password').setAttribute('aria-label', show ? 'Hide password' : 'Show password');
};

$('auth-form').onsubmit = async event => {
  event.preventDefault(); if (busy) return;
  if (mode === 'register' && $('password').value !== $('confirm').value) {
    $('auth-notice').textContent = 'Passwords do not match.'; return;
  }
  busy = true; $('auth-submit').disabled = true;
  $('auth-notice').classList.remove('success');
  $('auth-notice').textContent = 'Connecting to your team…';
  try {
    const result = await request(`/api/${mode}`, {
      username: $('username').value.trim(), password: $('password').value,
      room: $('room').value.trim()
    });
    $('password').value = ''; $('confirm').value = '';
    $('password').type = 'password'; $('show-password').textContent = 'Show';
    $('show-password').setAttribute('aria-label', 'Show password');
    if (mode === 'register') {
      busy = false; setMode('login');
      $('auth-notice').classList.add('success');
      $('auth-notice').textContent = result.message;
      $('password').focus();
    } else {
      openRoom(result); poll();
    }
  } catch (error) {
    $('auth-notice').textContent = error.message === 'Failed to fetch' ? 'The web app is offline. Restart it and try again.' : error.message;
  } finally {
    busy = false; $('auth-submit').disabled = false;
  }
};

function status(text, warning = false) {
  $('status-text').textContent = text;
  $('status').classList.toggle('warning', warning);
}
function setConnected(connected) {
  if (session) session.connected = connected;
  $('connection').classList.toggle('offline', !connected);
  $('connection').replaceChildren();
  const dot = document.createElement('span'); dot.className = 'dot';
  $('connection').append(dot, document.createTextNode(connected ? 'Connected' : 'Disconnected'));
  $('message').disabled = !connected;
  updateCount();
}
function openRoom(result) {
  generation++; session = {...result, connected: true};
  $('welcome').hidden = true; $('workspace').hidden = false;
  $('room-name').textContent = '# ' + result.room;
  $('account-name').textContent = result.username;
  $('user-avatar').textContent = result.username.slice(0, 1).toUpperCase();
  $('transport').textContent = tls ? 'Verified TLS to chat server' : 'Local connection';
  $('today').textContent = new Date().toLocaleDateString(undefined, {weekday: 'long', day: 'numeric', month: 'long'});
  setConnected(true); status('Room connected · Server security checks are active');
  systemMessage(result.verdict);
  $('message').focus();
}
function systemMessage(text) {
  const element = document.createElement('div');
  element.className = 'system-message' + (text.startsWith('[SECURITY]') || text.startsWith('[ERROR]') ? ' security' : '');
  element.textContent = text; $('messages').append(element); scrollMessages();
}
function addMessage(sender, text, own = false) {
  $('empty-chat').hidden = true;
  const row = document.createElement('div'); row.className = 'message-row' + (own ? ' own' : '');
  if (!own) {
    const avatar = document.createElement('span'); avatar.className = 'avatar';
    avatar.textContent = sender.slice(0, 1).toUpperCase(); row.append(avatar);
  }
  const content = document.createElement('div'); content.className = 'message-content';
  const meta = document.createElement('div'); meta.className = 'message-meta';
  const name = document.createElement('span'); name.textContent = own ? 'You · submitted' : sender;
  const time = document.createElement('time'); time.textContent = new Date().toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
  meta.append(name, time);
  const bubble = document.createElement('div'); bubble.className = 'bubble'; bubble.textContent = text;
  bubble.dir = 'auto'; content.append(meta, bubble); row.append(content); $('messages').append(row);
  scrollMessages();
}
function scrollMessages() {
  // Bound local history to keep long sessions responsive.
  const list = $('messages');
  while (list.children.length > 301) list.children[1].remove();
  list.scrollTop = list.scrollHeight;
}
async function poll() {
  if (!session) return;
  const current = generation;
  try {
    const result = await request('/api/events');
    if (current !== generation) return;
    for (const text of result.messages) {
      if (text.startsWith('[')) {
        systemMessage(text); status(text, true);
      } else {
        const split = text.indexOf(': ');
        addMessage(split < 0 ? 'Team' : text.slice(0, split), split < 0 ? text : text.slice(split + 2));
      }
    }
    setConnected(result.connected);
    if (!result.connected) {
      if (!result.messages.some(text => text.startsWith('[SECURITY]'))) status('Connection closed. Sign out and sign in again to reconnect.', true);
      return;
    }
  } catch (error) {
    if (current !== generation) return;
    setConnected(false); status(error.status === 401 ? 'Session expired. Sign out and sign in again.' : 'Connection interrupted. Trying again…', true);
    if (error.status === 401) return;
  }
  if (current === generation) pollTimer = setTimeout(poll, 700);
}
let sending = false;
function updateCount() {
  const size = encoder.encode($('message').value).length;
  $('byte-count').textContent = `${size.toLocaleString()} / ${messageLimit.toLocaleString()} bytes`;
  $('byte-count').classList.toggle('over-limit', size > messageLimit);
  $('send').disabled = sending || !session?.connected || size > messageLimit || !$('message').value.trim();
}
$('message').oninput = updateCount;
$('composer').onsubmit = async event => {
  event.preventDefault();
  if ($('send').disabled) return;
  const text = $('message').value, current = generation;
  sending = true; updateCount();
  try {
    await request('/api/send', {message: text});
    if (generation !== current) return;
    addMessage(session.username, text, true);
    if ($('message').value === text) $('message').value = '';
  } catch (error) { if (generation === current) status(error.message, true); }
  finally { sending = false; updateCount(); }
};
$('copy-room').onclick = async () => {
  try { await navigator.clipboard.writeText(session.room); status('Invite code copied. Share it with your team.'); }
  catch { status('Copy this room code: ' + session.room); }
};
$('logout').onclick = async () => {
  $('logout').disabled = true;
  try {
    await request('/api/logout', {});
    generation++; clearTimeout(pollTimer); session = null;
    $('workspace').hidden = true; $('welcome').hidden = false;
    $('message').value = '';
    [...$('messages').children].forEach(child => {if (child.id !== 'empty-chat') child.remove();});
    $('empty-chat').hidden = false;
    $('auth-notice').textContent = 'You left the room. Join another whenever you are ready.';
    $('password').focus();
  } catch { status('Could not sign out. Check that the web app is still running, then retry.', true); }
  finally { $('logout').disabled = false; }
};
async function initialize() {
  try {
    const settings = await request('/api/settings');
    messageLimit = settings.messageLimit; tls = settings.tls;
    $('password-hint').textContent = `${settings.passwordMin}+ characters`;
    const existing = await request('/api/events');
    openRoom(existing);
    for (const text of existing.messages) {
      if (text.startsWith('[')) systemMessage(text);
      else {const split = text.indexOf(': '); addMessage(text.slice(0, split), text.slice(split + 2));}
    }
    setConnected(existing.connected);
    if (existing.connected) poll();
    else status('Connection closed. Sign out and sign in again.', true);
  } catch (error) {
    if (error.status !== 401) $('auth-notice').textContent = 'Cannot reach the web app. Start it, then reload this page.';
  }
}
initialize();
