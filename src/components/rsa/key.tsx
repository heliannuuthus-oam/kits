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
import { DefaultTextArea, RsaEncryptionForm } from "../../pages/encryption/rsa";
import { TextSelectCodec } from "../codec/TextCodecSelect";
import { useRef, useState } from "react";
import { RsaSelectConvert } from "../converter/RsaConvertSelect";
import {
	ConvertRef,
	Pkcs8Encoding,
	PkcsEncoding,
	PkcsEncodings,
	rsaConverter,
} from "../converter/converter";
import { textCodecor } from "../codec/codec";
import { invoke } from "@tauri-apps/api";

const keyHeight = 200;
const keyButtonHeight = 32;
const keyButtonWidth = 120;
const keyValidator: FormRule[] = [
	{ required: true, message: "key is required" },
];

const keySizes: SelectProps["options"] = [2048, 3072, 4096].map((bit) => {
	return {
		value: bit,
		label: <span>{bit}</span>,
	};
});

export const RsaKey = () => {
	const form = Form.useFormInstance<RsaEncryptionForm>();
	const [generating, setGenerating] = useState<boolean>(false);
	const rsaConverterEl = useRef<ConvertRef>(null);
	const _getPrivateKey = async (): Promise<Uint8Array> => {
		const encoding = form.getFieldValue("keyTextEncoding");
		return await textCodecor.decode(encoding, form.getFieldValue("privateKey"));
	};

	const _derivePublicKey = async (
		key: Uint8Array | null
	): Promise<Uint8Array> => {
		if (key == null) {
			key = await _getPrivateKey();
		}

		const encoding: PkcsEncoding =
			form.getFieldValue("encoding") || Pkcs8Encoding.PKCS8_PEM;

		return await invoke<Uint8Array>("derive_rsa", {
			key: key,
			...PkcsEncodings[encoding],
		});
	};
	const derivePublicKey = async () => {
		try {
			const publicKeyBytes = await _derivePublicKey(null);
			const encoding = form.getFieldValue("keyTextEncoding");
			const publicKey = await textCodecor.encode(encoding, publicKeyBytes);
			form.setFieldsValue({ publicKey });
		} catch (error) {
			console.log(error);
		}
	};
	const generatePrivateKey = async () => {
		console.log(form.getFieldsValue());

		setGenerating(true);
		try {
			const pkcsEncoding: PkcsEncoding = form.getFieldValue("keyEncoding");
			const keySize: number = form.getFieldValue("keySize");
			const privateKeyBytes = await invoke<Uint8Array>("generate_rsa", {
				keySize,
				...PkcsEncodings[pkcsEncoding],
			});

			const encoding = form.getFieldValue("keyTextEncoding");
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

	return (
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
					<Flex gap={22} justify="start" vertical style={{ height: keyHeight }}>
						<Form.Item noStyle name="keyEncoding">
							<RsaSelectConvert
								ref={rsaConverterEl}
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
							/>
						</Form.Item>
						<Form.Item noStyle name="keyTextEncoding">
							<TextSelectCodec
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
						<Form.Item noStyle name="keySize">
							<Select
								disabled={generating}
								options={keySizes}
								style={{
									minWidth: keyButtonWidth,
									minHeight: keyButtonHeight,
								}}
							/>
						</Form.Item>
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
	);
};
