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
} from "antd";
import { useRef, useState } from "react";
import { Codec, CodecRef, Formatter, decode } from "../codec";

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
	format: Formatter;
};

const AesInput = ({
	setOutput,
}: {
	setOutput: (ciphertext: Uint8Array) => void;
}) => {
	const [form] = Form.useForm<FormInput>();
	const [keySize, setKeySize] = useState<number>(128);
	const [operation, setOperation] = useState<string>("encrypt");
	const initialValues = { mode: Mode.CBC, padding: Padding.Pkcs7Padding };
	const codecEl = useRef<CodecRef>(null);
	const mode = Form.useWatch("mode", form);

	const keyValidator: FormRule[] = [
		{ required: true, message: "key is required" },
		{
			len: keySize === 128 ? 24 : 48,
			message: `iv must be a base64 encoded character of ${
				keySize === 128 ? 24 : 48
			} length`,
		},
	];

	const ivValidator: FormRule[] = [
		{ required: true, message: "iv is required" },
		{
			len: mode && mode === Mode.GCM ? 18 : 24,

			message: `iv must be a base64 encoded character of  ${
				mode && mode === Mode.GCM ? 18 : 24
			} length`,
		},
	];

	const inputValidator: FormRule[] = [
		{ required: true, message: "input is required" },
		{
			min: 1,

			message: "message must not be empty",
		},
	];

	const generateKey = async () => {
		const data: string = await invoke<string>("generate_aes", {
			keySize: keySize,
		});
		form.setFieldsValue({ key: data });
	};

	const generateIv = async () => {
		const data = await invoke<string>("generate_iv", {
			size: mode === Mode.CBC ? 16 : 12,
		});
		form.setFieldsValue({ iv: data });
	};

	const encryptOrDecrypt = async () => {
		console.log("form: ", form.getFieldsValue());
		const input = await decode(
			codecEl.current?.getFormat() || Formatter.Base64,
			form.getFieldValue("input")
		);

		if (operation === "encrypt") {
			invoke<Uint8Array>("encrypt_aes", {
				...form.getFieldsValue(),
				input,
			})
				.then(setOutput)
				.catch(console.log);
		} else {
			invoke<Uint8Array>("decrypt_aes", {
				...form.getFieldsValue(),
				input,
			})
				.then(setOutput)
				.catch(console.log);
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
							<Form.Item hasFeedback noStyle name="iv" rules={ivValidator}>
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
								<Form.Item noStyle name="iv" rules={ivValidator}>
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
			<Form.Item key="basic">
				<Row justify="space-between" align="middle">
					<Col>
						<Title style={{ margin: 0 }} level={5}>
							input:
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
			<Form.Item key="key">
				<Space.Compact size={size} style={{ width: "100%" }}>
					<Form.Item noStyle name="key" hasFeedback rules={keyValidator}>
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

			<Form.Item key="operation">
				<Row justify="space-between" align="middle">
					<Col>
						<Codec
							ref={codecEl}
							props={{
								size: size,
								defaultValue: Formatter.UTF8,
								options:
									operation === "encrypt"
										? [
												{ value: Formatter.UTF8, label: <span>utf8</span> },
												{ value: Formatter.Base64, label: <span>base64</span> },
												{ value: Formatter.Hex, label: <span>hex</span> },
											]
										: [
												{ value: Formatter.Base64, label: <span>base64</span> },
												{ value: Formatter.Hex, label: <span>hex</span> },
											],
							}}
							setInput={(input: string) =>
								form.setFieldsValue({ input: input })
							}
							getInput={() => form.getFieldValue("input")}
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
														onClick={(_) => {
															setOperation("encrypt");
															codecEl.current?.setFormat(Formatter.UTF8);
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
															codecEl.current?.setFormat(Formatter.Base64);
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
