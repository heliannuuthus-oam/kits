// @ts-check

import eslintConfigPrettier from "eslint-config-prettier";
import eslintTs from "@typescript-eslint/eslint-plugin";
import eslintHooksPlugin from "eslint-plugin-react-hooks";
import eslintTsParser from "@typescript-eslint/parser";
import eslintFunctional from "eslint-plugin-functional";

export default [
	{
		languageOptions: {
			parser: eslintTsParser,
			parserOptions: {
				ecmaFeatures: { modules: true },
				ecmaVersion: "latest",
				project: "./tsconfig.json",
			},
		},
		files: ["src/**/*.tsx", "src/**/*.ts"],
		ignores: [
			"src-tauri/**",
			"virtual:",
			"~react-pages",
			"**/*.d.*",
			"**/*.map.*",
			"**/*.js",
			"**/*.mjs",
			"**/*.cjs",
		],
		plugins: {
			functional: eslintFunctional,
			"@typescript-eslint": eslintTs,
			ts: eslintTs,
			"react-hook": eslintHooksPlugin,
		},
		rules: {
			...eslintTs.configs["eslint-recommended"].rules,
			...eslintTs.configs["recommended"].rules,
			"@typescript-eslint/no-unused-vars": "off",
		},
	},
	eslintConfigPrettier,
];
