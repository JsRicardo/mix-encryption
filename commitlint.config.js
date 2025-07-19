export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "type-enum": [
      2,
      "always",
      ["feature", "chore", "fix", "docs", "refactor", "test", "style", "perf"]
    ],
    "type-case": [2, "always", "lower-case"],
    "type-empty": [2, "never"],
    "subject-empty": [2, "never"],
    "header-pattern": [2, "always", /^(\w+): .+$/]
  }
};