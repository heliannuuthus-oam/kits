import { DownOutlined } from "@ant-design/icons";
import { invoke } from "@tauri-apps/api";
import {
	Button,
	Col,
	Dropdown,
	Form,
	FormRule,
	Input,
	Row,
	Select,
	Space,
	Typography,
	notification,
} from "antd";
import { useRef, useState } from "react";
import {
	TextRadioCodec,
	TextCodecRef,
	TextEncoding,
	textCodecor,
} from "../codec/TextCodecRadio";

const { TextArea } = Input;

const { Title } = Typography;

enum Mode {
	ECB = "ECB",
	CBC = "CBC",
	GCM = "GCM",
}

enum Padding {
	Pkcs7Padding = "Pkcs7Padding",
	NoPadding = "NoPadding",
}

const size = "middle";

type FormInput = {
	iv?: string;
	key: string;
	padding: Padding;
	mode: Mode;
	aad?: string;
	input: string;
	format: TextEncoding;
};

const ivComputer = (mode: Mode, encoding: TextEncoding): number => {
	let length = mode === Mode.CBC ? 16 : 12;
	switch (encoding) {
		case TextEncoding.Base64:
			length = Math.floor((length + 2) / 3) * 4;
			break;
		case TextEncoding.Hex:
			length *= 2;
			break;
	}
	return Math.floor(length);
};

const keyComputer = (keySize: number, encoding: TextEncoding): number => {
	let length = keySize / 8;
	switch (encoding) {
		case TextEncoding.Base64:
			length = Math.floor((length + 2) / 3) * 4;
			break;
		case TextEncoding.Hex:
			length *= 2;
			break;
	}
	return length;
};

const AesInput = ({
	setOutput,
}: {
	setOutput: (ciphertext: Uint8Array) => void;
}) => {
	const [form] = Form.useForm<FormInput>();
	const [keySize, setKeySize] = useState<number>(128);
	const [operation, setOperation] = useState<string>("encrypt");
	const initialValues = {
		mode: Mode.CBC,
		padding: Padding.Pkcs7Padding,
		iv: "",
		key: "",
	};
	const codecEl = useRef<TextCodecRef>(null);
	const mode = Form.useWatch("mode", form);
	const [notifyApi, notifyContextHodler] = notification.useNotification({
		stack: { threshold: 1 },
	});

	const notify = (description: unknown) => {
		notifyApi.error({
			message: `${operation} failed`,
			description: description as string,
			duration: 3,
			placement: "bottomRight",
		});
	};

	const keyValidator: FormRule[] = [
		{ required: true, message: "key is required" },
		({ getFieldValue }) => ({
			validator(_, value) {
				const encoding = codecEl.current?.getEncoding() || TextEncoding.Base64;
				const length = keyComputer(keySize, encoding);
				if (!value || getFieldValue("key").length === length) {
					return Promise.resolve();
				}
				return Promise.reject(
					new Error(
						`key must be a ${encoding} encodings character of ${length} length`
					)
				);
			},
		}),
	];

	const ivValidator: FormRule[] = [
		{ required: true, message: "iv is required" },
		({ getFieldValue }) => ({
			validator(_, value) {
				const encoding = codecEl.current?.getEncoding() || TextEncoding.Base64;
				const length = ivComputer(mode, encoding);
				if (!value || getFieldValue("iv").length === length) {
					return Promise.resolve();
				}
				return Promise.reject(
					new Error(
						`iv must be a ${encoding} encodings character of ${length} length`
					)
				);
			},
		}),
	];

	const inputValidator: FormRule[] = [
		{ required: true, message: "input is required" },
		{
			min: 1,
			message: "message must not be empty",
		},
	];

	const generateKey = async () => {
		try {
			const dataBytes = await invoke<Uint8Array>("generate_aes", {
				keySize: keySize,
			});
			const data = await textCodecor.encode(
				codecEl.current?.getEncoding() || TextEncoding.Base64,
				dataBytes
			);

			form.setFieldsValue({ key: data });
		} catch (err: unknown) {
			notify(err);
		}
	};

	const generateIv = async () => {
		try {
			const dataBytes = await invoke<Uint8Array>("generate_iv", {
				size: mode === Mode.CBC ? 16 : 12,
			});

			const data = await textCodecor.encode(
				codecEl.current?.getEncoding() || TextEncoding.Base64,
				dataBytes
			);

			form.setFieldsValue({ iv: data });
		} catch (err: unknown) {
			notify(err);
		}
	};

	const encryptOrDecrypt = async () => {
		try {
			const eencoding = codecEl.current?.getEncoding() || TextEncoding.Base64;
			await form.validateFields({ validateOnly: true });
			const input = await textCodecor.decode(
				eencoding,
				form.getFieldValue("input")
			);
			const iv = await textCodecor.decode(eencoding, form.getFieldValue("iv"));
			const key = await textCodecor.decode(
				eencoding,
				form.getFieldValue("key")
			);
			let output;
			if (operation === "encrypt") {
				output = await invoke<Uint8Array>("encrypt_aes", {
					...form.getFieldsValue(),
					input,
					iv,
					key,
				});
			} else {
				output = await invoke<Uint8Array>("decrypt_aes", {
					...form.getFieldsValue(),
					input,
					iv,
					key,
				});
			}
			setOutput(output);
		} catch (err: unknown) {
			setOutput(new Uint8Array());
		}
	};

	const onValuesChange = (value: object) => {
		if (Object.keys(value).indexOf("mode") !== -1) {
			form.setFieldsValue({ key: undefined, iv: undefined });
		}
	};

	const renderExtract = (mode: Mode): React.ReactElement => {
		switch (mode) {
			case Mode.CBC:
				return (
					<Form.Item key="cbc_iv">
						<Space.Compact size={size} style={{ width: "100%" }}>
							<Form.Item
								hasFeedback
								noStyle
								name="iv"
								dependencies={["mode"]}
								rules={ivValidator}
							>
								<Input placeholder="input iv" />
							</Form.Item>
							<Button style={{ margin: 0 }} onClick={generateIv}>
								generate iv
							</Button>
						</Space.Compact>
					</Form.Item>
				);

			case Mode.GCM:
				return (
					<>
						<Form.Item key="gcm_iv" hasFeedback>
							<Space.Compact size={size} style={{ width: "100%" }}>
								<Form.Item
									noStyle
									name="iv"
									dependencies={["mode"]}
									rules={ivValidator}
									hasFeedback
								>
									<Input placeholder="input iv" />
								</Form.Item>
								<Button style={{ margin: 0 }} onClick={generateIv}>
									generate iv
								</Button>
							</Space.Compact>
						</Form.Item>
						<Form.Item key="gcm_aad" name="aad">
							<Input placeholder="input aad" />
						</Form.Item>
					</>
				);
			default:
				return <></>;
		}
	};

	const changeOperator = async () => {
		try {
			const fromEncoding =
				codecEl.current?.getEncoding() || TextEncoding.Base64;
			const toEncoding = TextEncoding.Base64;
			const values = form.getFieldsValue(["iv", "key"]);
			const iv = await textCodecor.encode(
				toEncoding,
				await textCodecor.decode(fromEncoding, values["iv"])
			);
			const key = await textCodecor.encode(
				toEncoding,
				await textCodecor.decode(fromEncoding, values["key"])
			);
			form.setFieldsValue({ input: "", iv, key });
			codecEl.current?.setEncoding(toEncoding);
		} catch (error) {
			console.log(error);
		}
	};

	return (
		<Form
			form={form}
			onValuesChange={onValuesChange}
			initialValues={initialValues}
			layout="vertical"
			size={size}
			style={{ width: "100%", padding: 24 }}
			validateTrigger="onBlur"
		>
			{notifyContextHodler}
			<Form.Item key="basic">
				<Row justify="space-between" align="middle">
					<Col>
						<Title style={{ margin: 0 }} level={5}>
							Input:
						</Title>
					</Col>
					<Col>
						<Form.Item noStyle name="mode">
							<Select
								size={size}
								options={[
									{ value: Mode.ECB, label: <span>AES_ECB</span> },
									{ value: Mode.CBC, label: <span>AES_CBC</span> },
									{ value: Mode.GCM, label: <span>AES_GCM</span> },
								]}
							/>
						</Form.Item>
					</Col>
					<Col>
						<Form.Item noStyle name="padding">
							<Select
								size={size}
								options={[
									{
										value: Padding.Pkcs7Padding,
										label: <span>Pkcs7Padding</span>,
									},
									{ value: Padding.NoPadding, label: <span>NoPadding</span> },
								]}
							/>
						</Form.Item>
					</Col>
				</Row>
			</Form.Item>
			<Form.Item key="operation">
				<Row justify="space-between" align="middle">
					<Col>
						<TextRadioCodec
							codecor={textCodecor}
							ref={codecEl}
							props={{
								size: size,
								defaultValue: TextEncoding.UTF8,
								options: [
									{
										value: TextEncoding.UTF8,
										label: <span>utf-8</span>,
									},
									{
										value: TextEncoding.Base64,
										label: <span>base64</span>,
									},
									{ value: TextEncoding.Hex, label: <span>hex</span> },
								],
							}}
							setInputs={(inputs: Record<string, string>) =>
								form.setFieldsValue({ ...inputs })
							}
							getInputs={() => form.getFieldsValue(["key", "iv"])}
						/>
					</Col>
					<Col>
						<Col>
							<Space.Compact>
								<Dropdown.Button
									menu={{
										items: [
											{
												label: (
													<div
														onClick={async (_) => {
															setOperation("encrypt");
															await changeOperator();
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
														onClick={async (_) => {
															setOperation("decrypt");
															await changeOperator();
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
							</Space.Compact>
						</Col>
					</Col>
				</Row>
			</Form.Item>
			<Form.Item key="key">
				<Space.Compact size={size} style={{ width: "100%" }}>
					<Form.Item
						noStyle
						name="key"
						dependencies={["mode"]}
						hasFeedback
						rules={keyValidator}
					>
						<Input placeholder="input encryption key" />
					</Form.Item>
					<Select
						defaultValue={keySize}
						onChange={setKeySize}
						style={{ width: 150 }}
						options={[
							{ value: 128, label: <span>128bit</span> },
							{ value: 256, label: <span>256bit</span> },
						]}
					/>
					<Button style={{ margin: 0 }} onClick={generateKey}>
						generate key
					</Button>
				</Space.Compact>
			</Form.Item>
			{renderExtract(mode)}

			<Form.Item key="input">
				<div
					style={{
						height: 560,
					}}
				>
					<Form.Item noStyle name="input" rules={inputValidator}>
						<TextArea style={{ height: "100%", resize: "none" }} />
					</Form.Item>
				</div>
			</Form.Item>
		</Form>
	);
};

export default AesInput;
