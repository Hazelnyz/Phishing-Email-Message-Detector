// Local-only Ollama chat. Conversation state stays in this page's memory.
document.addEventListener("DOMContentLoaded", function () {
  var root = document.getElementById("pgChat");
  if (!root) return;

  var panel = document.getElementById("pgChatPanel");
  var openButton = document.getElementById("pgChatOpen");
  var closeButton = document.getElementById("pgChatClose");
  var form = document.getElementById("pgChatForm");
  var input = document.getElementById("pgChatInput");
  var sendButton = document.getElementById("pgChatSend");
  var list = document.getElementById("pgChatMessages");
  var statusText = document.getElementById("pgChatStatus");
  var statusDot = document.getElementById("pgChatStatusDot");
  var unavailable = document.getElementById("pgChatUnavailable");
  var setupHint = document.getElementById("pgChatSetupHint");
  var typing = document.getElementById("pgChatTyping");
  var typingText = document.getElementById("pgChatTypingText");
  var errorBox = document.getElementById("pgChatError");
  var history = [];
  var available = false;
  var pending = false;

  function appendMessage(role, text, save) {
    var item = document.createElement("div");
    item.className = "pg-chat-message " + (role === "user" ? "pg-chat-message-user" : "pg-chat-message-assistant");
    item.setAttribute("data-role", role);
    item.textContent = text;
    list.appendChild(item);
    list.scrollTop = list.scrollHeight;
    if (save) {
      history.push({ role: role, content: text });
      if (history.length > 6) history = history.slice(-6);
    }
  }

  function setUnavailable(reason) {
    available = false;
    statusDot.classList.remove("is-available");
    statusText.textContent = "Assistant unavailable";
    setupHint.textContent = reason || "Start Ollama locally and install a model such as llama3.2:3b.";
    unavailable.hidden = false;
    input.disabled = true;
    sendButton.disabled = true;
  }

  function clearError() {
    errorBox.textContent = "";
    errorBox.hidden = true;
  }

  function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
  }

  function checkStatus() {
    fetch("/api/chat/status", { headers: { "Accept": "application/json" } })
      .then(function (response) { return response.json().then(function (body) { return { ok: response.ok, body: body }; }); })
      .then(function (result) {
        if (!result.ok || !result.body.available) {
          setUnavailable(result.body.reason);
          return;
        }
        available = true;
        statusDot.classList.add("is-available");
        statusText.textContent = "Local model ready: " + result.body.model;
        unavailable.hidden = true;
        input.disabled = false;
        sendButton.disabled = false;
      })
      .catch(function () { setUnavailable("Could not reach the local assistant. Start Ollama and try again."); });
  }

  function sendQuestion(question) {
    if (!available || pending) return;
    question = String(question || "").trim();
    if (!question) return;
    clearError();
    var priorHistory = history.slice(-6);
    appendMessage("user", question, true);
    pending = true;
    sendButton.disabled = true;
    typing.hidden = false;
    typingText.textContent = "Thinking…";
    var slowTimer = window.setTimeout(function () {
      typingText.textContent = "Loading the model, the first reply can take up to a minute.";
    }, 3000);

    var payload = {
      question: question,
      history: priorHistory,
      message: root.dataset.message || undefined,
      sender: root.dataset.sender || undefined,
      url: root.dataset.url || undefined
    };
    fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(payload)
    }).then(function (response) {
      return response.json().then(function (body) { return { status: response.status, body: body }; });
    }).then(function (result) {
      if (result.status === 400 || result.status === 429) {
        showError(result.body.error || "The request could not be processed.");
        return;
      }
      if (result.status < 200 || result.status >= 300) {
        showError("The assistant request failed. Please try again.");
        return;
      }
      appendMessage("assistant", result.body.answer || "The assistant returned no reply.", true);
      if (!result.body.available) setUnavailable("The local Ollama request failed. Start Ollama and try again.");
    }).catch(function () {
      showError("Could not reach the assistant. Check that the local service is running.");
    }).finally(function () {
      window.clearTimeout(slowTimer);
      typing.hidden = true;
      pending = false;
      sendButton.disabled = !available;
      list.scrollTop = list.scrollHeight;
    });
  }

  function openPanel() {
    panel.hidden = false;
    panel.setAttribute("aria-hidden", "false");
    openButton.setAttribute("aria-expanded", "true");
    input.focus();
  }

  function closePanel() {
    panel.hidden = true;
    panel.setAttribute("aria-hidden", "true");
    openButton.setAttribute("aria-expanded", "false");
    openButton.focus();
  }

  openButton.addEventListener("click", openPanel);
  closeButton.addEventListener("click", closePanel);
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && !panel.hidden) closePanel();
  });

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var question = input.value;
    if (!question.trim()) return;
    input.value = "";
    sendQuestion(question);
  });
  input.addEventListener("keydown", function (event) {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      form.requestSubmit();
    }
  });
  document.querySelectorAll("[data-question]").forEach(function (chip) {
    chip.addEventListener("click", function () { sendQuestion(chip.dataset.question); });
  });
  document.getElementById("pgChatClear").addEventListener("click", function () {
    list.replaceChildren();
    history = [];
    clearError();
    appendMessage("assistant", "Ask me about the analysis result or phishing safety.", false);
  });

  appendMessage("assistant", "Ask me about the analysis result or phishing safety.", false);
  checkStatus();
});
