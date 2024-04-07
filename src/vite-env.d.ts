/// <reference types="vite/client" />
/// <reference types="vite-plugin-pages/client-react" />
/// <reference types="vite-plugin-pages/client" />

interface ImportMetaEnv {
	readonly VITE_PROCESSOR_SERVER_URL: string;
	readonly VITE_REQUEST_TIMEOUT: number;
}

interface ImportMeta {
	readonly env: ImportMetaEnv;
}
