import { invoke } from "@tauri-apps/api";
import {
	Button,
	Col,
	Form,
	FormRule,
	Input,
	Row,
	Select,
	Space,
	Typography,
} from "antd";
import { useState } from "react";

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

const AesInput = ({
	setCiphertext,
}: {
	setCiphertext: (ciphertext: Uint8Array) => void;
}) => {
	const [form] = Form.useForm<{
		iv?: string;
		key: string;
		padding: Padding;
		mode: Mode;
		aad?: string;
	}>();

	const [keySize, setKeySize] = useState<number>(128);
	const initialValues = { mode: Mode.CBC, padding: Padding.Pkcs7Padding };

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

	const encrypt = async () => {
		console.log("form: ", form.getFieldsValue());
		const ciphertext = await invoke<Uint8Array>(
			"encrypt_aes",
			form.getFieldsValue()
		);
		setCiphertext(ciphertext);
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
									{ value: Mode.ECB, label: <span>ECB</span> },
									{ value: Mode.CBC, label: <span>CBC</span> },
									{ value: Mode.GCM, label: <span>GCM</span> },
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
					<Col>
						<Button
							htmlType="submit"
							color="green"
							size={size}
							style={{ margin: 0 }}
							onClick={encrypt}
						>
							encrypt
						</Button>
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

			<Form.Item key="plaintext">
				<div
					style={{
						height: 590,
					}}
				>
					<Form.Item noStyle name="plaintext" rules={[{ required: true }]}>
						<TextArea style={{ height: "100%", resize: "none" }} />
					</Form.Item>
				</div>
			</Form.Item>
		</Form>
	);
};

export default AesInput;
