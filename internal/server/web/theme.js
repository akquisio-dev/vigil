"use strict";
// Loaded before the stylesheet so a page set to dark never flashes light.
try {
  const theme = localStorage.getItem("vigil.theme");
  if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
} catch { /* storage blocked: follow the system setting */ }
