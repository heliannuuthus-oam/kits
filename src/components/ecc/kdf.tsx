import { Form, Select, Space } from "antd";
import { useEffect, useState } from "react";
import { getDigests, getEciesEncAlgs, getKdfs } from "../../api/constants";
import { TextEncoding } from "../codec/codec";

export type EciesEncryptionForm = {
	curveName: string;
	privateKey: string;
	publicKey: string;
	kdf: string;
	kdfDigest: string;
	salt: string | null;
	saltEncoding: TextEncoding | null;
	info: string | null;
	infoEncoding: TextEncoding | null;
	input: string | null;
	inputEncoding: TextEncoding;
	output: string | null;
	outputEncoding: TextEncoding;
	encryptionAlg: string;
	forEncryption: boolean;
};

const size = "middle";

export const EciesKdf = () => {
	const [kdfs, setKdfs] = useState<string[]>([""]);
	const [kdfDigests, setKdfDigests] = useState<string[]>([""]);
	const [eciesEncAlgs, setEciesEncAlgs] = useState<string[]>([""]);
	const form = Form.useFormInstance<EciesEncryptionForm>();

	useEffect(() => {
		getKdfs().then((k) => {
			setKdfs(k);
			form.setFieldsValue({
				kdf: k[0],
			});
		});
		getDigests().then((d) => {
			d = d.slice(1);
			setKdfDigests(d);
			form.setFieldsValue({
				kdfDigest: d[0],
			});
		});

		getEciesEncAlgs().then((d) => {
			setEciesEncAlgs(d);
			form.setFieldsValue({
				encryptionAlg: d[0],
			});
		});
	}, [
		getKdfs,
		getDigests,
		getEciesEncAlgs,
		setKdfs,
		setKdfDigests,
		setEciesEncAlgs,
		form,
	]);

	return (
		<Space.Compact size={size} style={{ width: "100%" }}>
			<Form.Item noStyle key="kdf" name="kdf" style={{ width: "100%" }}>
				<Select
					options={kdfs.map((kdf) => {
						return {
							label: kdf.toLocaleLowerCase(),
							value: kdf,
						};
					})}
				/>
			</Form.Item>
			<Form.Item
				noStyle
				key="kdfDigest"
				name="kdfDigest"
				style={{ width: "100%" }}
			>
				<Select
					size={size}
					options={kdfDigests.map((digest) => {
						return {
							label: digest.toLocaleLowerCase(),
							value: digest,
						};
					})}
				/>
			</Form.Item>
			<Form.Item
				key="encryptionAlg"
				name="encryptionAlg"
				style={{ width: "100%" }}
			>
				<Select
					options={eciesEncAlgs.map((e) => {
						return {
							label: e.toLocaleLowerCase(),
							value: e,
						};
					})}
				/>
			</Form.Item>
		</Space.Compact>
	);
};
