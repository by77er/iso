(() => {
  const root = document.documentElement;
  const system = window.matchMedia("(prefers-color-scheme: dark)");
  let preference = "system";
  try {
    const saved = localStorage.getItem("iso-theme");
    if (["light", "dark", "system"].includes(saved)) preference = saved;
  } catch {
    // Follow the system theme when browser storage is unavailable.
  }
  root.dataset.themePreference = preference;
  const apply = () => {
    root.dataset.theme =
      root.dataset.themePreference === "system"
        ? system.matches
          ? "dark"
          : "light"
        : root.dataset.themePreference;
  };
  apply();
  system.addEventListener("change", apply);
})();
