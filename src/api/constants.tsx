import { invoke } from "@tauri-apps/api";

const fetchKdfs = async (): Promise<string[]> => {
	return await invoke<string[]>("kdfs");
};

const fetchDigests = async (): Promise<string[]> => {
	return await invoke<string[]>("digests");
};

const fetchEciesEncAlgs = async (): Promise<string[]> => {
	return await invoke<string[]>("ecies_enc_alg");
};

export const fetchJwkeyTypes = async (): Promise<string[]> => {
	return await invoke<string[]>("jwkey_type");
};

export const fetchJwkeyAlgs = async (kty: string): Promise<string[]> => {
	return await invoke<string[]>("jwkey_algorithm", { kty });
};

export const fetchJwkeyUsages = async (kty: string): Promise<string[]> => {
	return await invoke<string[]>("jwkey_usage", { kty });
};

export const randomId = async (): Promise<string> => {
	return await invoke<string>("random_id");
};

export { fetchDigests, fetchEciesEncAlgs, fetchKdfs };
