import { invoke } from "@tauri-apps/api";

export const fetchKdfs = async (): Promise<string[]> => {
	return await invoke<string[]>("kdfs");
};

export const fetchDigests = async (): Promise<string[]> => {
	return await invoke<string[]>("digests");
};

export const fetchEciesEncAlgs = async (): Promise<string[]> => {
	return await invoke<string[]>("ecies_enc_alg");
};
