import { useState } from "react";
import { Monitor, Moon, Sun } from "lucide-react";

export default function ThemePicker() {
  const [theme, setTheme] = useState(
    () => document.documentElement.dataset.themePreference || "system",
  );
  const Icon = theme === "system" ? Monitor : theme === "dark" ? Moon : Sun;
  return (
    <label className="theme-picker">
      <Icon size={16} aria-hidden="true" />
      <select
        aria-label="Color theme"
        value={theme}
        onChange={(event) => {
          const value = event.target.value;
          setTheme(value);
          document.documentElement.dataset.themePreference = value;
          document.documentElement.dataset.theme =
            value === "system"
              ? window.matchMedia("(prefers-color-scheme: dark)").matches
                ? "dark"
                : "light"
              : value;
          try {
            localStorage.setItem("iso-theme", value);
          } catch {
            // The selected theme still works when storage is unavailable.
          }
        }}
      >
        <option value="system">System theme</option>
        <option value="light">Light mode</option>
        <option value="dark">Dark mode</option>
      </select>
    </label>
  );
}
