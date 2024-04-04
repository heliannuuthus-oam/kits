module.exports = {
	env: {
		browser: true,
		es2021: true,
	},
	root: true,
	extends: [
		"eslint:recommended",
		"plugin:eslint-plugin/recommended",
		"plugin:deprecation/recommended",
		"plugin:@typescript-eslint/recommended",
		"plugin:prettier/recommended",
	],
	parser: "@typescript-eslint/parser",

	overrides: [
		{
			env: {
				node: true,
			},
			files: [".eslintrc.{js,cjs}"],
			parserOptions: {
				sourceType: "script",
			},
		},
	],

	parserOptions: {
		ecmaVersion: "latest",
		sourceType: "module",
		ecmaFeatures: {
			jsx: true,
		},
		project: ["./tsconfig.json"],
	},
	plugins: ["@typescript-eslint", "react"],
	ignorePatterns: [".eslintrc.cjs", "vite.config.ts", "dist"],
	rules: {
		"@typescript-eslint/prefer-nullish-coalescing": "off",
		"@typescript-eslint/no-unused-vars": [
			"error",
			{ varsIgnorePattern: "^_", argsIgnorePattern: "^_" },
		],
		curly: ["error", "all"],
		eqeqeq: [
			"error",
			"always",
			{
				null: "never",
			},
		],
		"@typescript-eslint/quotes": [
			"error",
			"double",
			{ avoidEscape: true, allowTemplateLiterals: false },
		],
		semi: "error",
		"prefer-const": "error",
		indent: ["error", "tab"],
		"prettier/prettier": [
			"error",
			{
				trailingComma: "es5",
				tabWidth: 2,
				semi: true,
				singleQuote: false,
				useTabs: true,
			},
		],
	},
};
