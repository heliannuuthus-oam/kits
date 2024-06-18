import { invoke } from "@tauri-apps/api";

const fetchCurveNames = async (): Promise<string[]> => {
	return await invoke<string[]>("elliptic_curve");
};

export { fetchCurveNames };
