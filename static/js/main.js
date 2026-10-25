// Minimal client-side enhancement: character counter for the message textarea.
// No external network calls are made from this file.
document.addEventListener("DOMContentLoaded", function () {
  var menuButton = document.querySelector(".menu-toggle");
  var menu = document.querySelector("#navMenu");
  if (menuButton && menu) {
    menuButton.addEventListener("click", function () {
      var open = menuButton.getAttribute("aria-expanded") === "true";
      menuButton.setAttribute("aria-expanded", String(!open));
      menu.classList.toggle("is-open", !open);
    });
  }

  var textarea = document.querySelector("textarea[name='message']");
  if (textarea) {
    var counter = document.createElement("div");
    counter.className = "form-text character-count";
    counter.setAttribute("aria-live", "polite");
    textarea.insertAdjacentElement("afterend", counter);
    function update() { counter.textContent = textarea.value.length + " / 5000 characters"; }
    textarea.addEventListener("input", update);
    update();
    document.querySelectorAll("[data-sample]").forEach(function (chip) {
      chip.addEventListener("click", function () {
        textarea.value = chip.getAttribute("data-sample");
        textarea.dispatchEvent(new Event("input", { bubbles: true }));
        textarea.focus();
      });
    });
    var form = document.querySelector("#analysisForm");
    if (form) form.addEventListener("submit", function () {
      var button = form.querySelector("button[type='submit']");
      if (button) { button.disabled = true; button.textContent = "Analyzing…"; }
      var skeleton = document.getElementById("loadingSkeleton");
      if (skeleton) skeleton.hidden = false;
    });
  }

  var result = document.querySelector("#analysisResult");
  if (result && document.querySelector(".pg-result")) result.focus();
  var copy = document.querySelector("#copyReport");
  if (copy && result) copy.addEventListener("click", async function () {
    var status = document.querySelector("#copyStatus");
    var summary = result.innerText.replace(/\s+/g, " ").trim();
    try {
      await navigator.clipboard.writeText(summary);
      status.textContent = "Report summary copied. Links are defanged.";
    } catch (error) { status.textContent = "Copy was unavailable in this browser."; }
  });
});
