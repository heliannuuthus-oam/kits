import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import eslint from "@nabla/vite-plugin-eslint";
import pages from "vite-plugin-pages";

// https://vitejs.dev/config/
export default defineConfig(async ({ command, mode }) => {
	process.env = { ...process.env, ...loadEnv(mode, process.cwd()) };
	return {
		plugins: [react(), eslint(), pages()],
		build: {
			rollupOptions: {
				output: {
					manualChunks(id) {
						if (id.includes("node_modules")) {
							return id
								.toString()
								.split("node_modules/")[1]
								.split("/")[0]
								.toString();
						}
					},
				},
			},
		},
		// Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
		//
		// 1. prevent vite from obscuring rust errors
		clearScreen: false,
		// 2. tauri expects a fixed port, fail if that port is not available
		server: {
			host: "0.0.0.0",
			port: 11420,
			strictPort: true,
			watch: {
				// 3. tell vite to ignore watching `src-tauri`
				ignored: ["**/src-tauri/**"],
			},
			proxy: {
				"/processor": {
					target: process.env.VITE_PROCESSOR_SERVER_URL,
					changeOrigin: true,
					rewrite: (path) => path.replace(/^\/processor/, ""),
				},
			},
		},
	};
});
