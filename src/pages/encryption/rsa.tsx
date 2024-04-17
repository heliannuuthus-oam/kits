import { invoke } from "@tauri-apps/api";
import {
	Button,
	Col,
	Dropdown,
	Flex,
	Form,
	FormItemProps,
	FormRule,
	Row,
	Select,
	SelectProps,
	Typography,
} from "antd";
import TextArea, { TextAreaProps } from "antd/es/input/TextArea";
import { useRef, useState } from "react";
import {
	CharCodec,
	CharCodecRef,
	CharFormatter,
	charCodecor,
} from "../../components/codec/CharCodec";
import { DownOutlined } from "@ant-design/icons";

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

type FormatFormItem = {
	value: Format;
	validateStatus?: FormItemProps["validateStatus"];
	errorMsg?: FormItemProps["help"];
};

const size = "middle";
const keyHeight = 200;
const RsaEncryption = () => {
	const [form] = Form.useForm<RsaEncryptionForm>();
	const [operation, setOperation] = useState<string>("encrypt");
	const [keySize, setKeySize] = useState<number>(2048);
	const padding = Form.useWatch("padding", form);
	const digest = Form.useWatch("digest", form);
	const [format, setFormat] = useState<FormatFormItem>({
		value: Format.Pkcs8_PEM,
	});
	const [generating, setGenerating] = useState<boolean>(false);
	const [deriving, setDeriving] = useState<boolean>(false);
	const privateKeyCodecEl = useRef<CharCodecRef>(null);
	const publicKeyCodecEl = useRef<CharCodecRef>(null);
	const inputCodecEl = useRef<CharCodecRef>(null);
	const outputCodecEl = useRef<CharCodecRef>(null);
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
				format: format.value,
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
				format: format.value,
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
		try {
			const parameters = await form.validateFields({ validateOnly: true });
			const input = await charCodecor.decode(
				inputCodecEl.current?.getFormat() || CharFormatter.UTF8,
				parameters.input || ""
			);
			console.log(parameters);
			let output;
			if (operation === "encrypt") {
				const key = await charCodecor.decode(
					publicKeyCodecEl.current?.getFormat() || CharFormatter.Base64,
					parameters.publicKey
				);

				output = await invoke<Uint8Array>("encrypt_rsa", {
					data: {
						...parameters,
						input,
						format: format.value,
						key: key,
					},
				});
			} else {
				const key = await charCodecor.decode(
					privateKeyCodecEl.current?.getFormat() || CharFormatter.Base64,
					parameters.privateKey
				);

				output = await invoke<Uint8Array>("decrypt_rsa", {
					data: {
						...parameters,
						input,
						format: format.value,
						key: key,
					},
				});
			}

			form.setFieldsValue({
				output: await charCodecor.encode(
					outputCodecEl.current?.getFormat() || CharFormatter.Base64,
					output
				),
			});
		} catch (err) {
			console.log(err);
		}
	};

	const formatChange = async (to: Format) => {
		try {
			let { privateKey: privateKeyStr, publicKey: publicKeyStr } =
				await form.validateFields(["privateKey", "publicKey"]);

			const [privateKey, publicKey] = await Promise.all([
				charCodecor.decode(CharFormatter.Base64, privateKeyStr),
				charCodecor.decode(CharFormatter.Base64, publicKeyStr),
			]);

			const [privateKeyBytes, publicKeyByte] = await invoke<Array<Uint8Array>>(
				"transfer_key",
				{
					privateKey,
					publicKey,
					to,
					from: format.value,
				}
			);
			[privateKeyStr, publicKeyStr] = await Promise.all([
				charCodecor.encode(CharFormatter.Base64, privateKeyBytes),
				charCodecor.encode(CharFormatter.Base64, publicKeyByte),
			]);
			setFormat({ value: to });
			form.setFieldsValue({
				privateKey: privateKeyStr,
				publicKey: publicKeyStr,
			});
		} catch (err) {
			console.log(err);
		}
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
			<Form.Item key="key">
				<Row justify="space-between" align="middle">
					<Col span={10}>
						<Flex
							align="center"
							justify="space-between"
							style={{ padding: "24px 0" }}
						>
							<Typography.Title level={5} style={{ margin: 0 }}>
								PrivateKey
							</Typography.Title>
							<CharCodec
								codecor={charCodecor}
								ref={privateKeyCodecEl}
								props={{
									size: size,
									defaultValue: CharFormatter.Base64,
								}}
								setInput={(input: string) =>
									form.setFieldsValue({ privateKey: input })
								}
								getInput={() => form.getFieldValue("privateKey")}
							/>
						</Flex>
						<Form.Item name="privateKey" rules={keyValidator}>
							<DefaultTextArea
								disabled={generating}
								style={{ height: keyHeight }}
							/>
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
								style={{ minWidth: 90, minHeight: 32 }}
								type="primary"
							>
								derive
							</Button>
							<Select
								disabled={generating}
								value={keySize}
								onChange={setKeySize}
								options={keySizes}
								style={{ minWidth: 90, minHeight: 32 }}
							/>
							<Button
								loading={generating}
								type="primary"
								onClick={generatePrivateKey}
								style={{ minWidth: 90, minHeight: 32 }}
							>
								generate
							</Button>
						</Flex>
					</Col>
					<Col span={10}>
						<Flex
							align="center"
							justify="space-between"
							style={{ padding: "24px 0" }}
						>
							<Typography.Title level={5} style={{ margin: 0 }}>
								PrivateKey
							</Typography.Title>
							<CharCodec
								codecor={charCodecor}
								ref={publicKeyCodecEl}
								props={{
									size: size,
									defaultValue: CharFormatter.Base64,
								}}
								setInput={(input: string) =>
									form.setFieldsValue({ publicKey: input })
								}
								getInput={() => form.getFieldValue("publicKey")}
							/>
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

			<Form.Item key="baisc">
				<Row gutter={47} justify="space-between" align="middle">
					{renderExtract(padding)}
					<Col span={4}>
						<Form.Item noStyle name="padding">
							<Select style={{ minWidth: "8rem" }} options={paddings} />
						</Form.Item>
					</Col>

					<Col span={4}>
						<Form.Item
							noStyle
							help={format.errorMsg}
							validateStatus={format.validateStatus}
						>
							<Select
								value={format.value}
								onChange={formatChange}
								disabled={generating}
								style={{ minWidth: "7.5rem" }}
								options={formats}
							></Select>
						</Form.Item>
					</Col>

					<Col>
						<Dropdown.Button
							menu={{
								items: [
									{
										label: (
											<div
												onClick={(_) => {
													setOperation("encrypt");
													inputCodecEl.current?.setFormat(CharFormatter.UTF8);
												}}
											>
												encrypt
											</div>
										),
										key: "encrypt",
									},
									{
										label: (
											<div
												onClick={(_) => {
													setOperation("decrypt");
													inputCodecEl.current?.setFormat(CharFormatter.Base64);
												}}
											>
												decrypt
											</div>
										),
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
			<Form.Item>
				<Flex
					align="center"
					justify="space-between"
					style={{ padding: "0 0 24px 0" }}
				>
					<Typography.Title level={5} style={{ margin: 0 }}>
						Input
					</Typography.Title>
					<CharCodec
						codecor={charCodecor}
						ref={inputCodecEl}
						props={{
							size: size,
							defaultValue: CharFormatter.UTF8,
						}}
						setInput={(input: string) => form.setFieldsValue({ input })}
						getInput={() => form.getFieldValue("input")}
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
			<Form.Item>
				<Flex
					align="center"
					justify="space-between"
					style={{ padding: "0 0 24px 0" }}
				>
					<Typography.Title level={5} style={{ margin: 0 }}>
						Output
					</Typography.Title>
					<CharCodec
						codecor={charCodecor}
						ref={outputCodecEl}
						props={{
							size: size,
							defaultValue: CharFormatter.Base64,
						}}
						setInput={(input: string) => form.setFieldsValue({ output: input })}
						getInput={() => form.getFieldValue("output")}
					/>
				</Flex>
				<Form.Item key="output" name="output">
					<DefaultTextArea style={{ height: 150 }}></DefaultTextArea>
				</Form.Item>
			</Form.Item>
		</Form>
	);
};
export default RsaEncryption;
