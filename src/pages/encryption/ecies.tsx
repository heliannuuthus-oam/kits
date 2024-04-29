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
	Typography,
} from "antd";
import TextArea, { TextAreaProps } from "antd/es/input/TextArea";
import { useRef, useState } from "react";
import {
	TextCodecRef,
	TextEncoding,
	textCodecor,
} from "../../components/codec/codec";

import { TextRadioCodec } from "../../components/codec/TextCodecRadio";
import { TextSelectCodec } from "../../components/codec/TextCodecSelect";
import {
	Pkcs8Encoding,
	PkcsCodecRef,
	pkcsConverter,
	PkcsEncodings,
} from "../../components/converter/converter";
import { PkcsSelectConvert } from "../../components/converter/PkcsCodecSelect";

const DefaultTextArea = ({ style, ...props }: TextAreaProps) => {
	return <TextArea {...props} style={{ resize: "none", ...style }}></TextArea>;
};

type EciesEncryptionForm = {
	privateKey: string;
	publicKey: string;
	input: string | null;
	output: string | null;
};

const initialValues: EciesEncryptionForm = {
	privateKey: "",
	publicKey: "",
	input: null,
	output: null,
};

enum CurveName {
	NIST_P256 = "nistp256",
	NIST_P384 = "nistp384",
	NIST_P521 = "nistp521",
	Secp256k1 = "secp256k1",
}
const curveNames: SelectProps["options"] = (
	Object.keys(CurveName) as Array<keyof typeof CurveName>
).map((key) => {
	return {
		value: CurveName[key],
		label: <span>{CurveName[key].toString()}</span>,
	};
});

const size = "middle";
const keyHeight = 200;
const keyButtonHeight = 32;
const keyButtonWidth = 120;
const EciesEncryption = () => {
	const [form] = Form.useForm<EciesEncryptionForm>();
	const [curveName, setCurveName] = useState<CurveName>(CurveName.NIST_P256);
	const [generating, setGenerating] = useState<boolean>(false);
	const pkiKeyCodecEl = useRef<PkcsCodecRef>(null);
	const keyCodecEl = useRef<TextCodecRef>(null);
	const inputCodecEl = useRef<TextCodecRef>(null);
	const outputCodecEl = useRef<TextCodecRef>(null);

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
		const pkcs8Encoding =
			pkiKeyCodecEl.current?.getEncoding() || Pkcs8Encoding.PKCS8_PEM;
		return await invoke<Uint8Array>("derive_rsa", {
			key: key,
			format: pkcs8Encoding,
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
			const pkcs8Encoding =
				pkiKeyCodecEl.current?.getEncoding() || Pkcs8Encoding.PKCS8_PEM;
			const privateKeyBytes = await invoke<Uint8Array>("generate_ecc", {
				curveName: curveName,
				...PkcsEncodings[pkcs8Encoding],
			});
			const publicKeyBytes = await _derivePublicKey(privateKeyBytes);
			const encoding = keyCodecEl.current?.getEncoding() || TextEncoding.Base64;
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
						props={{
							size: size,
							defaultValue: TextEncoding.UTF8,
						}}
						setInputs={(input: Record<string, string>) =>
							form.setFieldsValue(input)
						}
						getInputs={() => form.getFieldsValue(["input"])}
					/>
				</Flex>
				<Form.Item key="input" name="input" rules={inputValidator}>
					<DefaultTextArea showCount style={{ height: 150 }}></DefaultTextArea>
				</Form.Item>
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
							<Form.Item noStyle>
								<PkcsSelectConvert
									converter={pkcsConverter}
									props={{
										disabled: generating,
										style: {
											minWidth: keyButtonWidth,
											minHeight: keyButtonHeight,
										},
									}}
									getInputs={() =>
										form.getFieldsValue(["privateKey", "publicKey"])
									}
									setInputs={(inputs: Record<string, Uint8Array>) =>
										form.setFieldsValue(inputs)
									}
									ref={pkiKeyCodecEl}
								/>
							</Form.Item>
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
								value={curveName}
								onChange={setCurveName}
								options={curveNames}
								style={{ minWidth: keyButtonWidth, minHeight: keyButtonHeight }}
							/>
							<TextSelectCodec
								ref={keyCodecEl}
								codecor={textCodecor}
								getInputs={() =>
									form.getFieldsValue(["privateKey", "publicKey"])
								}
								setInputs={form.setFieldsValue}
								props={{
									disabled: generating,
									style: {
										minWidth: keyButtonWidth,
										minHeight: keyButtonHeight,
									},
									defaultValue: TextEncoding.UTF8,
								}}
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
						props={{
							size: size,
							defaultValue: TextEncoding.Base64,
						}}
						setInputs={(inputs: Record<string, string>) =>
							form.setFieldsValue(inputs)
						}
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
export default EciesEncryption;
