(function () {
  "use strict";

  var scheme = "slate";
  var primary = "teal";
  var accent = "light-blue";

  function applyPalette() {
    var body = document.body;
    if (!body) return;

    body.setAttribute("data-md-color-scheme", scheme);
    body.setAttribute("data-md-color-primary", primary);
    body.setAttribute("data-md-color-accent", accent);

    try {
      var scope = window.__md_scope || new URL("..", location);
      var key = scope.pathname + ".__palette";
      var value = JSON.stringify({
        color: { media: "", scheme: scheme, primary: primary, accent: accent },
      });
      localStorage.setItem(key, value);
    } catch (_err) {
      // Non-fatal: page styling is still forced via data attributes.
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", applyPalette, { once: true });
  } else {
    applyPalette();
  }

  window.addEventListener("pageshow", applyPalette);
})();
