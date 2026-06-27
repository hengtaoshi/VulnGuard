import js from "@eslint/js";

export default [
  js.configs.recommended,
  {
    ignores: [".next/**", "node_modules/**", "dist/**", "release/**", "tools/**", "out/**"],
  },
  {
    rules: {
      "no-unused-vars": "warn",
      "no-undef": "off",
    },
  },
];
