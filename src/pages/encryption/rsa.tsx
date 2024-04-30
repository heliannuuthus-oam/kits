import { invoke } from "@tauri-apps/api";
import {
	Button,
	Col,
	Dropdown,
	Flex,
	Form,
	FormRule,
	Row,
	Select,
	SelectProps,
	Typography,
} from "antd";
import TextArea, { TextAreaProps } from "antd/es/input/TextArea";
import { useRef, useState } from "react";
import {
	TextCodecRef,
	TextEncoding,
	textCodecor,
} from "../../components/codec/codec";

import { DownOutlined } from "@ant-design/icons";
import { TextRadioCodec } from "../../components/codec/TextCodecRadio";
import { TextSelectCodec } from "../../components/codec/TextCodecSelect";
import {
	Pkcs8Encoding,
	PkcsEncodings,
	RsaConvertRef,
	RsaPkiEncoding,
	rsaConverter,
} from "../../components/converter/converter";
import { RsaSelectConvert } from "../../components/converter/RsaConvertSelect";

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

const keySizes: SelectProps["options"] = [2048, 3072, 4096].map((bit) => {
	return {
		value: bit,
		label: <span>{bit}</span>,
	};
});

const digestLength: Record<Digest, number> = {
	sha1: 160,
	sha256: 256,
	sha384: 384,
	sha512: 512,
	"sha3-256": 256,
	"sha3-384": 384,
	"sha3-512": 512,
};

const calcEncryptionMaxLength = (
	keySize: number,
	padding: Padding,
	digest?: Digest
): number => {
	switch (padding) {
		case Padding.Pkcs1_v15:
			return keySize / 8 - 11; // pkcs1_v1-5 padding length
		case Padding.Oaep:
			if (digest) {
				return keySize / 8 - (2 * digestLength[digest]) / 8 - 2;
			}
			return 0;
	}
};

type RsaEncryptionForm = {
	privateKey: string;
	publicKey: string;
	padding: Padding;
	digest?: Digest;
	mgfDigest?: Digest;
	input: string | null;
	output: string | null;
};

const initialValues: RsaEncryptionForm = {
	privateKey: "",
	publicKey: "",
	padding: Padding.Oaep,
	digest: Digest.Sha256,
	mgfDigest: Digest.Sha256,
	input: null,
	output: null,
};

const size = "middle";
const keyHeight = 200;
const keyButtonHeight = 32;
const keyButtonWidth = 120;
const RsaEncryption = () => {
	const [form] = Form.useForm<RsaEncryptionForm>();
	const [operation, setOperation] = useState<string>("encrypt");
	const [keySize, setKeySize] = useState<number>(2048);
	const padding = Form.useWatch("padding", form);
	const digest = Form.useWatch("digest", form);
	const rsaConvertEl = useRef<RsaConvertRef>(null);
	const [generating, setGenerating] = useState<boolean>(false);
	const keyCodecEl = useRef<TextCodecRef>(null);
	const inputCodecEl = useRef<TextCodecRef>(null);
	const outputCodecEl = useRef<TextCodecRef>(null);
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

	const _getPrivateKey = async (): Promise<Uint8Array> => {
		const encoding = keyCodecEl.current?.getEncoding() || TextEncoding.Base64;
		return await textCodecor.decode(encoding, form.getFieldValue("privateKey"));
	};

	const _derivePublicKey = async (
		key: Uint8Array | null
	): Promise<Uint8Array> => {
		if (key == null) {
			key = await _getPrivateKey();
		}
		const encoding =
			rsaConvertEl.current?.getEncoding() || Pkcs8Encoding.PKCS8_PEM;

		return await invoke<Uint8Array>("derive_rsa", {
			key: key,
			...PkcsEncodings[encoding],
		});
	};
	const derivePublicKey = async () => {
		try {
			const publicKeyBytes = await _derivePublicKey(null);
			const encoding = keyCodecEl.current?.getEncoding() || TextEncoding.Base64;
			const publicKey = await textCodecor.encode(encoding, publicKeyBytes);
			form.setFieldsValue({ publicKey });
		} catch (error) {
			console.log(error);
		}
	};
	const generatePrivateKey = async () => {
		setGenerating(true);
		try {
			const encoding = keyCodecEl.current?.getEncoding() || TextEncoding.Base64;

			const pkcsEncoding =
				rsaConvertEl.current?.getEncoding() || RsaPkiEncoding.PKCS8_PEM;
			const privateKeyBytes = await invoke<Uint8Array>("generate_rsa", {
				keySize: keySize,
				...PkcsEncodings[pkcsEncoding],
			});

			const publicKeyBytes = await _derivePublicKey(privateKeyBytes);
			const [publicKey, privateKey] = await Promise.all([
				textCodecor.encode(encoding, publicKeyBytes),
				textCodecor.encode(encoding, privateKeyBytes),
			]);

			form.setFieldsValue({
				publicKey,
				privateKey,
			});
		} catch (err) {
			console.log(err);
		}
		setGenerating(false);
	};

	const encryptOrDecrypt = async () => {
		try {
			const parameters = await form.validateFields({ validateOnly: true });
			const input = await textCodecor.decode(
				inputCodecEl.current?.getEncoding() || TextEncoding.UTF8,
				parameters.input || ""
			);
			const pkcsEncoding =
				rsaConvertEl.current?.getEncoding() || RsaPkiEncoding.PKCS8_PEM;
			let output;
			if (operation === "encrypt") {
				const key = await textCodecor.decode(
					keyCodecEl.current?.getEncoding() || TextEncoding.Base64,
					parameters.publicKey
				);

				output = await invoke<Uint8Array>("encrypt_rsa", {
					data: {
						...parameters,
						input,
						key: key,
						...PkcsEncodings[pkcsEncoding],
					},
				});
			} else {
				const key = await textCodecor.decode(
					keyCodecEl.current?.getEncoding() || TextEncoding.Base64,
					parameters.privateKey
				);

				output = await invoke<Uint8Array>("decrypt_rsa", {
					data: {
						...parameters,
						input,
						key: key,
						...PkcsEncodings[pkcsEncoding],
					},
				});
			}

			form.setFieldsValue({
				output: await textCodecor.encode(
					outputCodecEl.current?.getEncoding() || TextEncoding.Base64,
					output
				),
			});
		} catch (err) {
			console.log(err);
		}
	};

	const encryptToDecrypt = () => {
		setOperation("decrypt");
		form.setFieldsValue({ output: "", input: "" });
		inputCodecEl.current?.setEncoding(TextEncoding.Base64);
		outputCodecEl.current?.setEncoding(TextEncoding.UTF8);
	};

	const decryptToEncrypt = () => {
		setOperation("encrypt");
		form.setFieldsValue({ output: "", input: "" });
		inputCodecEl.current?.setEncoding(TextEncoding.UTF8);
		outputCodecEl.current?.setEncoding(TextEncoding.Base64);
	};

	return (
		<Form
			form={form}
			initialValues={initialValues}
			wrapperCol={{ span: 24 }}
			style={{ padding: "0 24px" }}
			layout="vertical"
			colon={true}
			validateTrigger="onBlur"
		>
			<Form.Item key="input">
				<Flex
					align="center"
					justify="space-between"
					style={{ padding: "24px 0 24px 0" }}
				>
					<Typography.Title level={5} style={{ margin: 0 }}>
						Input
					</Typography.Title>
					<TextRadioCodec
						codecor={textCodecor}
						ref={inputCodecEl}
						size={size}
						defaultValue={TextEncoding.UTF8}
						setInputs={(inputs: Record<string, string>) =>
							form.setFieldsValue(inputs)
						}
						getInputs={() => form.getFieldsValue(["input"])}
					/>
				</Flex>
				<Form.Item key="input" name="input" rules={inputValidator}>
					<DefaultTextArea
						count={{
							show: operation === "encrypt",
							max:
								operation === "encrypt"
									? calcEncryptionMaxLength(
											keySize,
											padding,
											padding === Padding.Oaep ? digest : undefined
										)
									: undefined,
						}}
						style={{ height: 150 }}
					></DefaultTextArea>
				</Form.Item>
			</Form.Item>

			<Form.Item key="baisc">
				<Row gutter={47} justify="space-between" align="middle">
					{renderExtract(padding)}
					<Col span={4}>
						<Form.Item noStyle name="padding">
							<Select style={{ minWidth: "8rem" }} options={paddings} />
						</Form.Item>
					</Col>

					<Col>
						<Dropdown.Button
							menu={{
								items: [
									{
										label: <div onClick={decryptToEncrypt}>encrypt</div>,
										key: "encrypt",
									},
									{
										label: <div onClick={encryptToDecrypt}>decrypt</div>,
										key: "decrypt",
									},
								],
							}}
							trigger={["hover"]}
							htmlType="submit"
							size={size}
							style={{ margin: 0 }}
							onClick={encryptOrDecrypt}
							icon={<DownOutlined />}
						>
							{operation}
						</Dropdown.Button>
					</Col>
				</Row>
			</Form.Item>

			<Form.Item key="key">
				<Row justify="space-between" align="top">
					<Col span={10}>
						<Flex
							align="center"
							justify="space-between"
							style={{ padding: "0 0 24px 0" }}
						>
							<Typography.Title level={5} style={{ margin: 0 }}>
								PrivateKey
							</Typography.Title>
						</Flex>
						<Form.Item name="privateKey" rules={keyValidator}>
							<DefaultTextArea
								disabled={generating}
								style={{ height: keyHeight }}
							/>
						</Form.Item>
					</Col>
					<Col span={4} style={{ padding: "0 15px" }}>
						<Flex
							gap={22}
							justify="start"
							vertical
							style={{ height: keyHeight }}
						>
							<Form.Item noStyle name="encoding">
								<RsaSelectConvert
									converter={rsaConverter}
									disabled={generating}
									style={{
										minWidth: keyButtonWidth,
										minHeight: keyButtonHeight,
									}}
									getInputs={() =>
										form.getFieldsValue(["privateKey", "publicKey"])
									}
									setInputs={form.setFieldsValue}
									ref={rsaConvertEl}
								/>
							</Form.Item>
							<TextSelectCodec
								ref={keyCodecEl}
								codecor={textCodecor}
								getInputs={() =>
									form.getFieldsValue(["privateKey", "publicKey"])
								}
								setInputs={form.setFieldsValue}
								disabled={generating}
								style={{
									minWidth: keyButtonWidth,
									minHeight: keyButtonHeight,
								}}
								defaultValue={TextEncoding.UTF8}
							/>
							<Button
								loading={generating}
								onClick={derivePublicKey}
								disabled={generating}
								style={{ minWidth: keyButtonWidth, minHeight: keyButtonHeight }}
								type="primary"
							>
								derive
							</Button>
							<Select
								disabled={generating}
								value={keySize}
								onChange={setKeySize}
								options={keySizes}
								style={{ minWidth: keyButtonWidth, minHeight: keyButtonHeight }}
							/>

							<Button
								loading={generating}
								type="primary"
								onClick={generatePrivateKey}
								style={{ minWidth: keyButtonWidth, minHeight: keyButtonHeight }}
							>
								generate
							</Button>
						</Flex>
					</Col>
					<Col span={10}>
						<Flex
							align="center"
							justify="space-between"
							style={{ padding: "0 0 24px 0" }}
						>
							<Typography.Title level={5} style={{ margin: 0 }}>
								PublicKey
							</Typography.Title>
						</Flex>
						<Form.Item name="publicKey" rules={keyValidator}>
							<DefaultTextArea
								disabled={generating}
								style={{ height: keyHeight }}
							/>
						</Form.Item>
					</Col>
				</Row>
			</Form.Item>

			<Form.Item key="output">
				<Flex
					align="center"
					justify="space-between"
					style={{ padding: "0 0 24px 0" }}
				>
					<Typography.Title level={5} style={{ margin: 0 }}>
						Output
					</Typography.Title>
					<TextRadioCodec
						codecor={textCodecor}
						ref={outputCodecEl}
						size={size}
						defaultValue={TextEncoding.Base64}
						setInputs={form.setFieldsValue}
						getInputs={() => form.getFieldsValue(["output"])}
					/>
				</Flex>
				<Form.Item key="output" name="output">
					<DefaultTextArea style={{ height: 150 }} showCount></DefaultTextArea>
				</Form.Item>
			</Form.Item>
		</Form>
	);
};
export default RsaEncryption;
