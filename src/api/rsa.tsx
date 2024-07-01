import { invoke } from "@tauri-apps/api";

const fetchRsaEncryptionPadding = async (): Promise<string[]> => {
	return await invoke<string[]>("rsa_encryption_padding");
};

export { fetchRsaEncryptionPadding };
