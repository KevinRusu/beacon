export default {
  content: ["./src/popup/**/*.{tsx,ts,html}"],
  // "class" not "media": the Dark Mode switch in Settings is an explicit user
  // choice that has to win over the OS setting. src/popup/theme.ts puts the
  // class on <html>.
  darkMode: "class",
  theme: { extend: {} },
  plugins: [],
};
