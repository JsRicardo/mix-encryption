import typescript from "@rollup/plugin-typescript";
import commonjs from "@rollup/plugin-commonjs";
import resolve from "@rollup/plugin-node-resolve";
import { terser } from "rollup-plugin-terser";
import dts from "rollup-plugin-dts";

const config = [
  {
    input: "src/index.ts",
    output: [
      {
        file: "dist/index.esm.js",
        format: "esm",
        sourcemap: true,
      },
      {
        file: "dist/index.cjs.js",
        format: "cjs",
        sourcemap: true,
      },
      {
        file: "dist/index.umd.js",
        format: "umd",
        name: "MixEncryption",
        sourcemap: true,
      },
    ],
    plugins: [
      resolve(),
      commonjs(),
      typescript({
        tsconfig: "./tsconfig.json",
        exclude: ["**/*.test.ts"],
      }),
      terser(),
    ],
    external: ["sm-crypto", "md5"],
  },
  {
    input: "src/index.ts",
    output: {
      file: "dist/types/index.d.ts",
      format: "es",
    },
    plugins: [dts()],
  },
];

export default config;
