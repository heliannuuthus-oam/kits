import { invoke } from "@tauri-apps/api";

const fetchRsaEncryptionPadding = async (): Promise<string[]> => {
	return await invoke<string[]>("rsa_encryption_padding");
};

const fetchRsaKeySize = async (): Promise<string[]> => {
	return await invoke<string[]>("rsa_key_size");
};

export { fetchRsaEncryptionPadding, fetchRsaKeySize };
