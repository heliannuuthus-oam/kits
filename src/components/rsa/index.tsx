import { invoke } from "@tauri-apps/api";
import { FormInstance } from "antd";
import { TextEncoding } from "../codec/codec";
import { PkcsFormat, PkcsFormats } from "../converter/converter";

export type RsaKeyDeriveForm = {
	privateKey: string;
	publicKey: string;
	pkcsFormat: PkcsFormat;
	encoding: TextEncoding;
	keySize: number | string;
};

export const deriveRsaKey = async (
	form: FormInstance<RsaKeyDeriveForm>,
	setGenerating: (generating: boolean) => void
) => {
	setGenerating(true);
	try {
		const { privateKey, pkcsFormat, encoding } = form.getFieldsValue([
			"privateKey",
			"pkcsFormat",
			"encoding",
		]);
		const pkcs = PkcsFormats[pkcsFormat as PkcsFormat];
		pkcs.setEncoding(encoding as TextEncoding);
		const publicKey = await invoke<string>("derive_rsa", {
			key: privateKey,
			...pkcs,
		});
		form.setFieldsValue({ publicKey });
	} catch (error) {
		console.log(error);
	}
	setGenerating(false);
};
export const generateRsaKey = async (form: FormInstance<RsaKeyDeriveForm>) => {
	try {
		const { keySize, encoding } = form.getFieldsValue(["keySize", "encoding"]);
		const pkcsFormat: PkcsFormat = form.getFieldValue("pkcsFormat");
		const pkcs = PkcsFormats[pkcsFormat];
		pkcs.setEncoding(encoding);
		const [privateKey, publicKey] = await invoke<string[]>("generate_rsa", {
			keySize,
			...pkcs,
		});

		form.setFieldsValue({
			publicKey,
			privateKey,
		});
	} catch (err) {
		console.log(err);
	}
};
