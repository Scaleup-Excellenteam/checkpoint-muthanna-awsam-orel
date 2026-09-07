const state = {
  mode: "login",
  token: sessionStorage.getItem("chatToken"),
  username: sessionStorage.getItem("chatUsername"),
  room: null,
  lastMessageId: 0,
  pollTimer: null,
  polling: false,
  config: null,
};

const $ = (selector) => document.querySelector(selector);
const encoder = new TextEncoder();

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body && typeof options.body !== "string") {
    headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(options.body);
  }
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const response = await fetch(path, { ...options, headers });
  const body = await response.json().catch(() => ({ error: "השרת החזיר תשובה לא תקינה." }));
  if (!response.ok) {
    const error = new Error(body.error || body.reason || "הפעולה נכשלה.");
    error.status = response.status;
    error.body = body;
    throw error;
  }
  return body;
}

function showScreen(id) {
  for (const screen of document.querySelectorAll(".screen")) screen.classList.add("hidden");
  $(id).classList.remove("hidden");
}

function setMessage(selector, message = "") {
  const element = $(selector);
  element.textContent = message;
  element.classList.toggle("hidden", !message);
}

function toast(message) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.remove("hidden");
  window.setTimeout(() => element.classList.add("hidden"), state.config.poll_interval_milliseconds * 2);
}

function initials(username) {
  return (username || "U").slice(0, 2).toUpperCase();
}

function setAuthMode(mode) {
  state.mode = mode;
  const registering = mode === "register";
  $("#login-tab").classList.toggle("active", !registering);
  $("#register-tab").classList.toggle("active", registering);
  $("#login-tab").setAttribute("aria-selected", String(!registering));
  $("#register-tab").setAttribute("aria-selected", String(registering));
  $("#confirm-label").classList.toggle("hidden", !registering);
  $("#confirm-wrap").classList.toggle("hidden", !registering);
  $("#password").autocomplete = registering ? "new-password" : "current-password";
  $("#auth-title").textContent = registering ? "מצטרפים ל־Slice Talk" : "נכנסים ל־Slice Talk";
  $("#auth-subtitle").textContent = registering
    ? "פותחים חשבון ומצטרפים לקהילה הכי טעימה ברשת."
    : "התחברו וגלו על מה חובבי הפיצה מדברים עכשיו.";
  $("#auth-submit").textContent = registering ? "הצטרפות לקהילה" : "כניסה לקהילה";
  setMessage("#auth-error");
  setMessage("#auth-success");
}

function saveSession(username, token) {
  state.username = username;
  state.token = token;
  sessionStorage.setItem("chatUsername", username);
  sessionStorage.setItem("chatToken", token);
}

function clearSession() {
  stopPolling();
  state.token = null;
  state.username = null;
  state.room = null;
  state.lastMessageId = 0;
  sessionStorage.removeItem("chatUsername");
  sessionStorage.removeItem("chatToken");
}

async function handleAuth(event) {
  event.preventDefault();
  setMessage("#auth-error");
  setMessage("#auth-success");
  const username = $("#username").value.trim();
  const password = $("#password").value;
  const usernameLength = username.length;
  const passwordBytes = encoder.encode(password).length;
  if (usernameLength < state.config.username_min_characters || usernameLength > state.config.username_max_characters) {
    setMessage("#auth-error", `שם המשתמש חייב להכיל ${state.config.username_min_characters}–${state.config.username_max_characters} תווים.`);
    return;
  }
  if (password.length < state.config.password_min_characters || passwordBytes > state.config.password_max_utf8_bytes) {
    setMessage("#auth-error", `הסיסמה חייבת להכיל לפחות ${state.config.password_min_characters} תווים.`);
    return;
  }
  if (state.mode === "register" && password !== $("#confirm-password").value) {
    setMessage("#auth-error", "הסיסמאות אינן זהות.");
    return;
  }
  $("#auth-submit").disabled = true;
  try {
    const result = await api(`/${state.mode}`, { method: "POST", body: { username, password } });
    if (state.mode === "register") {
      setAuthMode("login");
      $("#username").value = username;
      $("#password").value = "";
      $("#confirm-password").value = "";
      setMessage("#auth-success", "החשבון נוצר. עכשיו אפשר להתחבר.");
    } else {
      saveSession(result.username, result.token);
      await showHome();
    }
  } catch (error) {
    setMessage("#auth-error", error.message);
  } finally {
    $("#auth-submit").disabled = false;
  }
}

async function showHome() {
  stopPolling();
  state.room = null;
  $("#home-username").textContent = state.username;
  $("#home-avatar").textContent = initials(state.username);
  showScreen("#home-screen");
  await loadRooms();
}

async function loadRooms() {
  try {
    const result = await api("/rooms");
    renderRooms(result.rooms);
  } catch (error) {
    if (error.status === 401 || error.status === 403) return sessionEnded(error.message);
    toast(error.message);
  }
}

function renderRooms(rooms) {
  const grid = $("#rooms-grid");
  grid.replaceChildren();
  $("#room-count").textContent = `${rooms.length} שולחנות`;
  $("#rooms-empty").classList.toggle("hidden", rooms.length !== 0);
  for (const room of rooms) {
    const card = document.createElement("article");
    card.className = "room-card";
    const top = document.createElement("div");
    top.className = "room-card-top";
    const hash = document.createElement("span");
    hash.className = "room-hash";
    hash.textContent = "🍕";
    const activity = document.createElement("span");
    activity.className = "online-dot";
    top.append(hash, activity);
    const title = document.createElement("h3");
    title.textContent = room.name;
    const details = document.createElement("p");
    details.textContent = `${room.members} חובבי פיצה · ${room.messages} הודעות מהתנור`;
    const button = document.createElement("button");
    button.className = "secondary-button";
    button.type = "button";
    button.dataset.room = room.name;
    button.textContent = "הצטרפות לשולחן";
    card.append(top, title, details, button);
    grid.append(card);
  }
}

function validRoomLength(room) {
  return room.length >= state.config.room_min_characters && room.length <= state.config.room_max_characters;
}

async function createRoom(event) {
  event.preventDefault();
  setMessage("#create-error");
  const room = $("#new-room").value.trim();
  if (!validRoomLength(room)) return setMessage("#create-error", "אורך קוד השולחן אינו תקין.");
  try {
    await api("/rooms", { method: "POST", body: { room } });
    $("#new-room").value = "";
    enterRoom(room);
  } catch (error) {
    setMessage("#create-error", error.message);
  }
}

async function joinRoom(room, errorSelector = "#join-error") {
  setMessage(errorSelector);
  if (!validRoomLength(room)) return setMessage(errorSelector, "אורך קוד השולחן אינו תקין.");
  try {
    await api(`/rooms/${encodeURIComponent(room)}/join`, { method: "POST" });
    enterRoom(room);
  } catch (error) {
    setMessage(errorSelector, error.message);
  }
}

function enterRoom(room) {
  state.room = room;
  state.lastMessageId = 0;
  $("#messages").replaceChildren($("#chat-empty"));
  $("#chat-empty").classList.remove("hidden");
  for (const selector of ["#chat-room-name", "#aside-room-name"]) $(selector).textContent = room;
  $("#chat-username").textContent = state.username;
  $("#chat-avatar").textContent = initials(state.username);
  showScreen("#chat-screen");
  pollMessages();
  state.pollTimer = window.setInterval(pollMessages, state.config.poll_interval_milliseconds);
  $("#message-input").focus();
}

async function leaveRoom() {
  if (!state.room) return showHome();
  const room = state.room;
  try {
    await api(`/rooms/${encodeURIComponent(room)}/leave`, { method: "POST" });
  } catch (error) {
    if (error.status === 401 || error.status === 403) return sessionEnded(error.message);
  }
  await showHome();
}

function stopPolling() {
  if (state.pollTimer) window.clearInterval(state.pollTimer);
  state.pollTimer = null;
  state.polling = false;
}

async function pollMessages() {
  if (!state.room || state.polling) return;
  state.polling = true;
  try {
    const room = state.room;
    const result = await api(`/rooms/${encodeURIComponent(room)}/messages?after=${state.lastMessageId}`);
    if (room !== state.room) return;
    for (const message of result.messages) appendMessage(message);
  } catch (error) {
    if (error.status === 401 || error.status === 403) sessionEnded(error.message);
  } finally {
    state.polling = false;
  }
}

function appendMessage(message) {
  state.lastMessageId = Math.max(state.lastMessageId, message.id);
  $("#chat-empty")?.classList.add("hidden");
  const row = document.createElement("article");
  row.className = `message-row${message.username === state.username ? " mine" : ""}`;
  const avatar = document.createElement("div");
  avatar.className = "message-avatar";
  avatar.textContent = initials(message.username);
  const content = document.createElement("div");
  content.className = "message-content";
  const meta = document.createElement("div");
  meta.className = "message-meta";
  const author = document.createElement("strong");
  author.textContent = message.username === state.username ? "אני" : message.username;
  const timestamp = document.createElement("span");
  timestamp.textContent = new Date(message.timestamp * 1000).toLocaleTimeString("he-IL", { hour: "2-digit", minute: "2-digit" });
  meta.append(author, timestamp);
  const bubble = document.createElement("p");
  bubble.className = "bubble";
  bubble.textContent = message.text;
  content.append(meta, bubble);
  row.append(avatar, content);
  $("#messages").append(row);
  $("#messages").scrollTop = $("#messages").scrollHeight;
}

async function sendMessage(event) {
  event.preventDefault();
  const input = $("#message-input");
  const message = input.value.trim();
  if (!message) return;
  if (encoder.encode(message).length > state.config.message_bytes) {
    toast(`ההודעה גדולה מהמגבלה של ${state.config.message_bytes} bytes.`);
    return;
  }
  try {
    await api(`/rooms/${encodeURIComponent(state.room)}/messages`, { method: "POST", body: { message } });
    input.value = "";
    updateMessageSize();
    await pollMessages();
  } catch (error) {
    if (error.status === 401 || error.status === 403) return sessionEnded(error.message);
    toast(error.message);
  }
}

function updateMessageSize() {
  const size = encoder.encode($("#message-input").value).length;
  const counter = $("#message-size");
  counter.textContent = `${size} / ${state.config.message_bytes} bytes`;
  counter.classList.toggle("over", size > state.config.message_bytes);
}

function sessionEnded(message) {
  clearSession();
  showScreen("#auth-screen");
  setMessage("#auth-error", message || "ההתחברות הסתיימה. התחברו מחדש.");
}

async function logout() {
  try { await api("/logout", { method: "POST" }); } catch (_) { /* Session may already be gone. */ }
  clearSession();
  showScreen("#auth-screen");
  setMessage("#auth-success", "התנתקתם בהצלחה.");
}

async function initialize() {
  try {
    state.config = await api("/ui-config");
  } catch (_) {
    document.body.textContent = "לא ניתן לטעון את הגדרות האפליקציה.";
    return;
  }
  $("#login-tab").addEventListener("click", () => setAuthMode("login"));
  $("#register-tab").addEventListener("click", () => setAuthMode("register"));
  $("#toggle-password").addEventListener("click", () => {
    const input = $("#password");
    input.type = input.type === "password" ? "text" : "password";
  });
  $("#auth-form").addEventListener("submit", handleAuth);
  $("#create-room-form").addEventListener("submit", createRoom);
  $("#join-room-form").addEventListener("submit", (event) => {
    event.preventDefault();
    joinRoom($("#join-room").value.trim());
  });
  $("#rooms-grid").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-room]");
    if (button) joinRoom(button.dataset.room);
  });
  $("#refresh-rooms").addEventListener("click", loadRooms);
  $("#back-to-groups").addEventListener("click", leaveRoom);
  $("#aside-back").addEventListener("click", leaveRoom);
  $("#logout-button").addEventListener("click", logout);
  $("#message-form").addEventListener("submit", sendMessage);
  $("#message-input").addEventListener("input", updateMessageSize);
  $("#message-input").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      $("#message-form").requestSubmit();
    }
  });
  setAuthMode("login");
  updateMessageSize();
  if (state.token && state.username) await showHome();
  else showScreen("#auth-screen");
}

initialize();
