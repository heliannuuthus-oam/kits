import { invoke } from "@tauri-apps/api";
import { FormInstance, SelectProps } from "antd";
import { error } from "tauri-plugin-log-api";
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
		error(("ecc cuvename load failed" + e) as string);
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
	} catch (err) {
		error(err as string);
	}
	setGenerating(false);
};

export const generateEccKey = async (form: FormInstance) => {
	try {
		const {
			curveName,
			encoding,
			pkcsFormat,
		}: {
			curveName: string;
			encoding: TextEncoding;
			pkcsFormat: PkcsFormat;
		} = form.getFieldValue("elliptic_curve");
		const pkcs = PkcsFormats[pkcsFormat];
		pkcs.setEncoding(encoding);
		const [privateKey, publicKey] = await invoke<string[]>("generate_ecc", {
			curveName,
			...pkcs,
		});

		form.setFieldsValue({
			elliptic_curve: {
				publicKey,
				privateKey,
			},
		});
	} catch (err) {
		error(err as string);
	}
};
