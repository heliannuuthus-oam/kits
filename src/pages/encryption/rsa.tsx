import { invoke } from "@tauri-apps/api";
import {
	Button,
	Col,
	Flex,
	Form,
	FormRule,
	Row,
	Select,
	SelectProps,
} from "antd";
import { FormItemInputProps } from "antd/es/form/FormItemInput";
import TextArea, { TextAreaProps } from "antd/es/input/TextArea";
import { useState } from "react";
import { CharFormatter, charCodecor } from "../../components/codec/CharCodec";

const DefaultTextArea = ({ style, ...props }: TextAreaProps) => {
	return <TextArea {...props} style={{ resize: "none", ...style }}></TextArea>;
};

enum Digest {
	Sha1 = "sha1",
	Sha256 = "sha256",
	Sha384 = "sha384",
	Sha512 = "sha512",
	Sha3_256 = "sha3-256",
	Sha3_384 = "sha3-384",
	Sha3_512 = "sha3-512",
}

enum Padding {
	Pkcs1_v15 = "pkcs1-v1_5",
	Oaep = "oaep",
}

enum Format {
	Pkcs1_DER = "pkcs1-der",
	Pkcs1_PEM = "pkcs1-pem",
	Pkcs8_PEM = "pkcs8-pem",
	Pkcs8_DER = "pkcs8-der",
}

const digests: SelectProps["options"] = (
	Object.keys(Digest) as Array<keyof typeof Digest>
).map((key) => {
	return { value: Digest[key], label: <span>{Digest[key].toString()}</span> };
});

const paddings: SelectProps["options"] = (
	Object.keys(Padding) as Array<keyof typeof Padding>
).map((key) => {
	return { value: Padding[key], label: <span>{Padding[key].toString()}</span> };
});

const formats: SelectProps["options"] = (
	Object.keys(Format) as Array<keyof typeof Format>
).map((key) => {
	return { value: Format[key], label: <span>{Format[key].toString()}</span> };
});

const keySizes: SelectProps["options"] = [2048, 3072, 4096].map((bit) => {
	return {
		value: bit,
		label: <span>{bit}</span>,
	};
});

type RsaEncryptionForm = {
	privateKey: string;
	publicKey: string;
	padding: Padding;
	digest?: Digest;
	mgfDigest?: Digest;
	input: string;
	output: string;
};

const initialValues: RsaEncryptionForm = {
	privateKey: "",
	publicKey: "",
	padding: Padding.Oaep,
	digest: Digest.Sha256,
	mgfDigest: Digest.Sha256,
	input: "",
	output: "",
};

type FormatFormItem = {
	value: Format;
	validateStatus?: FormItemInputProps["status"];
	errorMsg?: FormItemInputProps["help"];
};

const RsaEncryption = () => {
	const [form] = Form.useForm<RsaEncryptionForm>();
	const [keySize, setKeySize] = useState<number>(2048);
	const padding = Form.useWatch("padding", form);
	const [format, setFormat] = useState<FormatFormItem>({
		value: Format.Pkcs8_PEM,
	});
	const [generating, setGenerating] = useState<boolean>(false);
	const [deriving, setDeriving] = useState<boolean>(false);
	const renderExtract = (padding: Padding) => {
		switch (padding) {
			case Padding.Pkcs1_v15:
				return [
					<Col key="oaep-digest-empty" span={4}></Col>,
					<Col key="oaep-mgf-digest-empty" span={4}></Col>,
				];
			case Padding.Oaep:
				return [
					<Col span={4} key="oaep-digest">
						<Form.Item noStyle name="digest">
							<Select options={digests} />
						</Form.Item>
					</Col>,
					<Col span={4} key="oaep-mgf-digest">
						<Form.Item noStyle name="mgfDigest">
							<Select options={digests} />
						</Form.Item>
					</Col>,
				];
		}
	};

	const keyValidator: FormRule[] = [
		{ required: true, message: "key is required" },
	];

	const inputValidator: FormRule[] = [
		{ required: true, message: "input is required" },
	];

	const derivePublicKey = async (key: Uint8Array | null) => {
		setDeriving(true);
		try {
			const privateKey =
				key == null
					? await charCodecor.decode(
							CharFormatter.Base64,
							form.getFieldValue("privateKey")
						)
					: key;

			const publicKeyByte = await invoke<Uint8Array>("derive_rsa", {
				key: privateKey,
				format: form.getFieldValue("format"),
			});

			const publicKey = await charCodecor.encode(
				CharFormatter.Base64,
				publicKeyByte
			);
			form.setFieldsValue({ publicKey: publicKey });
		} catch (err) {
			console.log(err);
		}
		setDeriving(false);
	};

	const generatePrivateKey = async () => {
		setGenerating(true);
		try {
			const privateKeyBytes = await invoke<Uint8Array>("generate_rsa", {
				keySize: keySize,
				format: form.getFieldValue("format"),
			});

			const [_, privateKey] = await Promise.all([
				derivePublicKey(privateKeyBytes),
				charCodecor.encode(CharFormatter.Base64, privateKeyBytes),
			]);

			form.setFieldsValue({
				privateKey,
			});
		} catch (err) {
			console.log(err);
		}
		setGenerating(false);
	};

	const encryptOrDecrypt = async () => {
		const cc = await form.validateFields({ validateOnly: true });
		console.log(cc);
	};

	const formatChange = async (to: Format) => {
		try {
			const { privateKey, publicKey } = await form.validateFields([
				"privateKey",
				"publicKey",
			]);
			const ca = await invoke("transfer_key", {
				privateKey,
				publicKey,
				to,
				from: format,
			});
			console.log(ca);
			setFormat({ value: to });
		} catch (err) {
			console.log(err);
		}
	};

	return (
		<Form
			form={form}
			initialValues={initialValues}
			wrapperCol={{ span: 24 }}
			style={{ padding: 24 }}
			layout="vertical"
			colon={true}
		>
			<Form.Item key="key">
				<Row justify="space-between" align="middle">
					<Col span={10}>
						<Form.Item
							name="privateKey"
							label="Private Key"
							rules={keyValidator}
						>
							<DefaultTextArea disabled={generating} style={{ height: 249 }} />
						</Form.Item>
					</Col>
					<Col span={3}>
						<Flex gap="middle" vertical>
							<Button
								loading={deriving}
								onClick={() => {
									setDeriving(true);
									derivePublicKey(null);
								}}
								disabled={generating}
								style={{ minWidth: 90, minHeight: 42 }}
								type="primary"
							>
								derive
							</Button>
							<Select
								disabled={generating}
								value={keySize}
								onChange={setKeySize}
								options={keySizes}
								style={{ minWidth: 90, minHeight: 42 }}
							/>
							<Button
								loading={generating}
								type="primary"
								onClick={generatePrivateKey}
								style={{ minWidth: 90, minHeight: 42 }}
							>
								generate
							</Button>
						</Flex>
					</Col>
					<Col span={10}>
						<Form.Item name="publicKey" label="Public Key" rules={keyValidator}>
							<DefaultTextArea disabled={generating} style={{ height: 249 }} />
						</Form.Item>
					</Col>
				</Row>
			</Form.Item>

			<Form.Item key="baisc">
				<Row gutter={47} justify="space-between" align="middle">
					{renderExtract(padding)}
					<Col span={4}>
						<Form.Item noStyle name="padding">
							<Select style={{ minWidth: "8rem" }} options={paddings} />
						</Form.Item>
					</Col>

					<Col span={4}>
						<Form.Item noStyle name="format">
							<Select
								onChange={formatChange}
								disabled={generating}
								style={{ minWidth: "7.5rem" }}
								options={formats}
							></Select>
						</Form.Item>
					</Col>

					<Col>
						<Button disabled={generating} onClick={encryptOrDecrypt}>
							encrypt
						</Button>
					</Col>
				</Row>
			</Form.Item>

			<Form.Item key="input" label="Input" rules={inputValidator}>
				<DefaultTextArea style={{ height: 150 }}></DefaultTextArea>
			</Form.Item>

			<Form.Item key="output" label="Output">
				<DefaultTextArea style={{ height: 150 }}></DefaultTextArea>
			</Form.Item>
		</Form>
	);
};
export default RsaEncryption;
