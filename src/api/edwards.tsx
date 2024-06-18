import { invoke } from "@tauri-apps/api";

const fetchEdwardsCuveNames = async (): Promise<string[]> => {
	return await invoke<string[]>("edwards");
};

export { fetchEdwardsCuveNames };
