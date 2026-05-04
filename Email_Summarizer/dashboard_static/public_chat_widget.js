// Discere public chat widget. Remove this file and its page includes to remove the widget.
(() => {
  const STORAGE_POSITION_KEY = "discerePublicChatPosition";
  const STORAGE_HISTORY_KEY = "discerePublicChatHistory";
  const MAX_HISTORY = 10;

  const starterPrompts = [
    "How do I start?",
    "Does Discere read all my email?",
    "How do scheduled summaries work?",
    "What does AI see?",
  ];

  let conversation = loadConversation();
  let isSending = false;
  let dragState = null;

  function createElement(tag, className, text = "") {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text) element.textContent = text;
    return element;
  }

  function loadConversation() {
    try {
      const parsed = JSON.parse(localStorage.getItem(STORAGE_HISTORY_KEY) || "[]");
      if (!Array.isArray(parsed)) return [];
      return parsed
        .filter((entry) => entry && ["user", "assistant"].includes(entry.role) && typeof entry.text === "string")
        .slice(-MAX_HISTORY);
    } catch {
      return [];
    }
  }

  function saveConversation() {
    localStorage.setItem(STORAGE_HISTORY_KEY, JSON.stringify(conversation.slice(-MAX_HISTORY)));
  }

  function loadPosition() {
    try {
      const parsed = JSON.parse(localStorage.getItem(STORAGE_POSITION_KEY) || "{}");
      if (Number.isFinite(parsed.left) && Number.isFinite(parsed.top)) return parsed;
    } catch {
      return null;
    }
    return null;
  }

  function savePosition(windowElement) {
    const rect = windowElement.getBoundingClientRect();
    localStorage.setItem(STORAGE_POSITION_KEY, JSON.stringify({ left: rect.left, top: rect.top }));
  }

  function clamp(value, min, max) {
    return Math.min(Math.max(value, min), max);
  }

  function applyPosition(windowElement, position) {
    if (!position) return;
    const rect = windowElement.getBoundingClientRect();
    const left = clamp(position.left, 12, window.innerWidth - rect.width - 12);
    const top = clamp(position.top, 12, window.innerHeight - rect.height - 12);
    windowElement.style.left = `${left}px`;
    windowElement.style.top = `${top}px`;
    windowElement.style.right = "auto";
    windowElement.style.bottom = "auto";
  }

  function renderMessages(messagesElement) {
    messagesElement.innerHTML = "";
    if (!conversation.length) {
      conversation = [
        {
          role: "assistant",
          text: "Ask me how Discere works. I can explain it simply, step by step.",
        },
      ];
    }
    conversation.forEach((entry) => {
      const message = createElement("div", `public-chat-message ${entry.role}`, entry.text);
      messagesElement.appendChild(message);
    });
    messagesElement.scrollTop = messagesElement.scrollHeight;
    saveConversation();
  }

  function setStatus(statusElement, text) {
    statusElement.textContent = text || "";
  }

  async function sendQuestion(question, elements) {
    const trimmed = String(question || "").trim();
    if (!trimmed || isSending) return;
    isSending = true;
    elements.sendButton.disabled = true;
    elements.input.disabled = true;
    setStatus(elements.status, "Thinking...");
    conversation.push({ role: "user", text: trimmed });
    renderMessages(elements.messages);
    elements.input.value = "";

    try {
      const response = await fetch("/public-chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          question: trimmed,
          conversation: conversation.slice(-8),
        }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.detail || "Ask Discere could not answer right now.");
      }
      conversation.push({
        role: "assistant",
        text: String(data.answer || "I could not answer that clearly. Try asking in a simpler way."),
      });
      setStatus(elements.status, "");
    } catch (error) {
      conversation.push({
        role: "assistant",
        text: "I could not answer right now. Please try again shortly.",
      });
      setStatus(elements.status, error.message || "Ask Discere is unavailable.");
    } finally {
      conversation = conversation.slice(-MAX_HISTORY);
      renderMessages(elements.messages);
      elements.sendButton.disabled = false;
      elements.input.disabled = false;
      elements.input.focus();
      isSending = false;
    }
  }

  function buildWidget() {
    const launcher = createElement("button", "public-chat-launcher", "Ask Discere");
    launcher.type = "button";
    launcher.setAttribute("aria-label", "Open Ask Discere chat");

    const windowElement = createElement("section", "public-chat-window");
    windowElement.hidden = true;
    windowElement.setAttribute("aria-label", "Ask Discere chat");

    const header = createElement("div", "public-chat-header");
    const headerText = createElement("div");
    headerText.appendChild(createElement("div", "public-chat-kicker", "Ask Discere"));
    headerText.appendChild(createElement("div", "public-chat-title", "Simple help with Discere"));
    const closeButton = createElement("button", "public-chat-close", "×");
    closeButton.type = "button";
    closeButton.setAttribute("aria-label", "Close Ask Discere chat");
    header.append(headerText, closeButton);

    const body = createElement("div", "public-chat-body");
    const messages = createElement("div", "public-chat-messages");
    const prompts = createElement("div", "public-chat-prompts");
    starterPrompts.forEach((prompt) => {
      const button = createElement("button", "public-chat-prompt", prompt);
      button.type = "button";
      button.addEventListener("click", () => sendQuestion(prompt, elements));
      prompts.appendChild(button);
    });

    const form = createElement("form", "public-chat-form");
    const input = createElement("input", "public-chat-input");
    input.type = "text";
    input.maxLength = 800;
    input.placeholder = "Ask how Discere works...";
    input.autocomplete = "off";
    const sendButton = createElement("button", "public-chat-send", "Send");
    sendButton.type = "submit";
    form.append(input, sendButton);
    const status = createElement("div", "public-chat-status");
    body.append(messages, prompts, form, status);
    windowElement.append(header, body);
    document.body.append(launcher, windowElement);

    const elements = { launcher, windowElement, header, closeButton, messages, input, sendButton, status };

    launcher.addEventListener("click", () => {
      windowElement.hidden = false;
      renderMessages(messages);
      applyPosition(windowElement, loadPosition());
      setTimeout(() => input.focus(), 0);
    });

    closeButton.addEventListener("click", () => {
      windowElement.hidden = true;
      launcher.focus();
    });

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      sendQuestion(input.value, elements);
    });

    header.addEventListener("pointerdown", (event) => {
      if (event.target === closeButton || window.innerWidth < 620) return;
      const rect = windowElement.getBoundingClientRect();
      dragState = {
        pointerId: event.pointerId,
        offsetX: event.clientX - rect.left,
        offsetY: event.clientY - rect.top,
      };
      windowElement.classList.add("is-dragging");
      header.setPointerCapture(event.pointerId);
      event.preventDefault();
    });

    header.addEventListener("pointermove", (event) => {
      if (!dragState || dragState.pointerId !== event.pointerId) return;
      const rect = windowElement.getBoundingClientRect();
      const left = clamp(event.clientX - dragState.offsetX, 12, window.innerWidth - rect.width - 12);
      const top = clamp(event.clientY - dragState.offsetY, 12, window.innerHeight - rect.height - 12);
      windowElement.style.left = `${left}px`;
      windowElement.style.top = `${top}px`;
      windowElement.style.right = "auto";
      windowElement.style.bottom = "auto";
    });

    header.addEventListener("pointerup", (event) => {
      if (!dragState || dragState.pointerId !== event.pointerId) return;
      dragState = null;
      windowElement.classList.remove("is-dragging");
      savePosition(windowElement);
    });

    window.addEventListener("resize", () => {
      if (!windowElement.hidden) applyPosition(windowElement, loadPosition());
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", buildWidget);
  } else {
    buildWidget();
  }
})();
