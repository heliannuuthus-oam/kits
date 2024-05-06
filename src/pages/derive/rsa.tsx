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
import { DefaultTextArea } from "../encryption/rsa";
import { useRef, useState } from "react";
import {
	TextCodecRef,
	TextEncoding,
	textCodecor,
} from "../../components/codec/codec";
import { useForm } from "antd/es/form/Form";
import {
	ConvertRef,
	Pkcs8Encoding,
	PkcsEncoding,
	PkcsEncodings,
	rsaConverter,
} from "../../components/converter/converter";
import { invoke } from "@tauri-apps/api";
import { RsaSelectConvert } from "../../components/converter/RsaConvertSelect";
import { TextSelectCodec } from "../../components/codec/TextCodecSelect";

const keySizes: SelectProps["options"] = [2048, 3072, 4096].map((bit) => {
	return {
		value: bit,
		label: <span>{bit}</span>,
	};
});

const keyHeight = 700;
const keyButtonHeight = 32;
const keyButtonWidth = 120;

export type RsaDeriveKeyForm = {
	privateKey: string;
	publicKey: string;
	pkcsEncoding: PkcsEncoding;
	textEncoding: TextEncoding;
	keySize: number;
};

const RsaDeriveKey = () => {
	const [form] = useForm<RsaDeriveKeyForm>();
	const rsaConvertEl = useRef<ConvertRef>(null);
	const keyCodecEl = useRef<TextCodecRef>(null);
	const [generating, setGenerating] = useState<boolean>(false);
	const initFormValue: RsaDeriveKeyForm = {
		privateKey: "",
		publicKey: "",
		pkcsEncoding: Pkcs8Encoding.PKCS8_PEM,
		textEncoding: TextEncoding.UTF8,
		keySize: 2048,
	};

	const keyValidator: FormRule[] = [
		{ required: true, message: "key is required" },
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

			const data = form.getFieldsValue(["keySize", "textEndocing"]);
			const pkcsEncoding: PkcsEncoding =
				form.getFieldValue("pkcsEncoding") || Pkcs8Encoding.PKCS8_PEM;

			const privateKeyBytes = await invoke<Uint8Array>("generate_rsa", {
				...data,
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
	return (
		<Form
			form={form}
			initialValues={initFormValue}
			wrapperCol={{ span: 24 }}
			style={{ padding: "0 24px" }}
			layout="vertical"
			colon={true}
			validateTrigger="onBlur"
		>
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
						gap={52}
						justify="center"
						vertical
						style={{ height: keyHeight }}
					>
						<Form.Item name="pkcsEncoding" label="pkcsEncoding">
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
						<Form.Item name="textEncoding" label="textEncoding">
							<TextSelectCodec
								ref={keyCodecEl}
								callback={rsaConvertEl.current?.setTextEncoding}
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
						<Form.Item name="keySize" label="keySize">
							<Select
								disabled={generating}
								options={keySizes}
								style={{ minWidth: keyButtonWidth, minHeight: keyButtonHeight }}
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
		</Form>
	);
};

export default RsaDeriveKey;
