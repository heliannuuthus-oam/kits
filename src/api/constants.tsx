import { invoke } from "@tauri-apps/api";

export const getKdfs = async (): Promise<string[]> => {
	return await invoke<string[]>("kdfs");
};

export const getDigests = async (): Promise<string[]> => {
	return await invoke<string[]>("digests");
};

export const getEciesEncAlgs = async (): Promise<string[]> => {
	return await invoke<string[]>("ecies_enc_alg");
};
