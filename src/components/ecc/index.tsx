import { invoke } from "@tauri-apps/api";
import { FormInstance, SelectProps } from "antd";
import { fetchCurveNames } from "../../api/ecc";
import { TextEncoding } from "../codec/codec";
import { PkcsFormat, PkcsFormats } from "../converter/converter";

export type EccKeyDeriveForm = {
	privateKey: string;
	publicKey: string;
	pkcsFormat: PkcsFormat;
	encoding: TextEncoding;
	curveName: string;
};

export const getEccCurveNames = async (): Promise<SelectProps["options"]> => {
	try {
		const curveNames = await fetchCurveNames();
		const formattedCurveNames = curveNames.map((curveName) => ({
			label: curveName,
			value: curveName,
		}));
		return formattedCurveNames;
	} catch (e) {
		console.log("ecc cuvename load failed", e);
	}
};

export const deriveEccKey = async (
	form: FormInstance<EccKeyDeriveForm>,
	setGenerating: (generating: boolean) => void
) => {
	setGenerating(true);
	try {
		const { curveName, privateKey, pkcsFormat, encoding } = form.getFieldsValue(
			["curveName", "privateKey", "pkcsFormat", "encoding"]
		);
		const pkcs = PkcsFormats[pkcsFormat as PkcsFormat];
		pkcs.setEncoding(encoding as TextEncoding);
		const publicKey = await invoke<string>("derive_ecc", {
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

export const generateEccKey = async (form: FormInstance<EccKeyDeriveForm>) => {
	try {
		const { curveName, encoding } = form.getFieldsValue([
			"curveName",
			"encoding",
		]);
		const pkcsFormat: PkcsFormat = form.getFieldValue("pkcsFormat");
		const pkcs = PkcsFormats[pkcsFormat];
		pkcs.setEncoding(encoding);
		const [privateKey, publicKey] = await invoke<string[]>("generate_ecc", {
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
