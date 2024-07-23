import { invoke } from "@tauri-apps/api";
import { FormInstance, SelectProps } from "antd";
import { fetchEdwardsCuveNames } from "../../api/edwards";
import { TextEncoding } from "../codec/codec";
import { PkcsFormat, PkcsFormats } from "../converter/converter";

export type EdwardsDeriveKeyForm = {
	privateKey: string;
	publicKey: string;
	pkcsFormat: PkcsFormat;
	encoding: TextEncoding;
	curveName: string;
};

export const getEdwardsCurveNames = async (): Promise<
	SelectProps["options"]
> => {
	try {
		const formatted = await fetchEdwardsCuveNames();
		return formatted.map((curveName) => ({
			label: curveName,
			value: curveName,
		}));
	} catch (error) {
		console.log("load edwards curve name failed");
	}
};

export const deriveEdwardsKey = async (
	form: FormInstance<EdwardsDeriveKeyForm>,
	setGenerating: (generating: boolean) => void
) => {
	setGenerating(true);
	try {
		const { curveName, privateKey, pkcsFormat, encoding } = form.getFieldsValue(
			["curveName", "privateKey", "pkcsFormat", "encoding"]
		);
		const pkcs = PkcsFormats[pkcsFormat as PkcsFormat];
		pkcs.setEncoding(encoding as TextEncoding);
		const publicKey = await invoke<string>("derive_edwards", {
			curveName,
			input: privateKey,
			...pkcs,
		});
		form.setFieldsValue({ publicKey });
	} catch (error) {
		console.log(error);
	}
	setGenerating(false);
};
export const generateEdwardsKey = async (
	form: FormInstance<EdwardsDeriveKeyForm>
) => {
	try {
		const { curveName, encoding } = form.getFieldsValue([
			"curveName",
			"encoding",
		]);
		const pkcsFormat: PkcsFormat = form.getFieldValue("pkcsFormat");
		console.log(pkcsFormat);

		const pkcs = PkcsFormats[pkcsFormat];
		pkcs.setEncoding(encoding);
		const [privateKey, publicKey] = await invoke<string[]>("generate_edwards", {
			curveName,
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
