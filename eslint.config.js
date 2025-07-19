import js from "@eslint/js"
import tseslint from "@typescript-eslint/eslint-plugin"
import tsparser from "@typescript-eslint/parser"

export default [
  js.configs.recommended,
  {
    files: ["src/**/*.ts"],
    ignores: ["dist/**", "node_modules/**", "*.d.ts"],
    languageOptions: {
      parser: tsparser,
      parserOptions: {
        ecmaVersion: "latest",
        sourceType: "module"
      },
      globals: {
        window: "readonly",
        Crypto: "readonly",
        crypto: "readonly",
        require: "readonly"
      }
    },
    plugins: {
      "@typescript-eslint": tseslint
    },
    rules: {
      "no-unused-vars": "off", // 关闭原生规则
      "@typescript-eslint/no-unused-vars": ["warn"], // 用TS专用规则
      semi: ["error", "always"],
      quotes: ["error", "double"],
      indent: ["error", 2],
      eqeqeq: ["error", "always"],
      "no-console": "warn",
    "curly": ["error", "multi-line"],
      "comma-dangle": ["error", "only-multiline"],
    }
  }
]