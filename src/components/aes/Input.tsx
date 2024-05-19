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
	notification,
} from "antd";
import { useState } from "react";
import { TextEncoding, textCodecor } from "../codec/codec";
import { EncryptionMode } from "./Setting";
import { AesForm } from "../../pages/encryption/aes";
import { OptionButton } from "../OptionButton";

const { TextArea } = Input;

const { Title } = Typography;

const size = "middle";

const ivComputer = (mode: EncryptionMode, encoding: TextEncoding): number => {
	let length = mode === EncryptionMode.CBC ? 16 : 12;
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
	setSettingOpen,
}: {
	setSettingOpen: (settingOpen: boolean) => void;
}) => {
	const form = Form.useFormInstance<AesForm>();
	const [keySize, setKeySize] = useState<number>(128);
	const mode = Form.useWatch("mode", form);
	const forEncryption = Form.useWatch("forEncryption", {
		form,
		preserve: true,
	});
	const [notifyApi, notifyContextHodler] = notification.useNotification({
		stack: { threshold: 1 },
	});

	const notify = (description: unknown) => {
		notifyApi.error({
			message: `${forEncryption ? "encrypt" : "decrypt"} failed`,
			description: description as string,
			duration: 3,
			placement: "bottomRight",
		});
	};

	const keyValidator: FormRule[] = [
		{ required: true, message: "key is required" },
		({ getFieldValue }) => ({
			validator(_, value) {
				const encoding = form.getFieldValue("keyEncoding");
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
				const encoding = form.getFieldValue("ivEncoding");
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
				form.getFieldValue("keyEncoding") || TextEncoding.Base64,
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
				size: mode === EncryptionMode.CBC ? 16 : 12,
			});
			const data = await textCodecor.encode(
				form.getFieldValue("ivEncoding"),
				dataBytes
			);

			form.setFieldsValue({ iv: data });
		} catch (err: unknown) {
			notify(err);
		}
	};

	const encryptOrDecrypt = async () => {
		try {
			await form.validateFields({ validateOnly: true });
			const input = form.getFieldValue("input");
			const iv =
				mode === EncryptionMode.ECB
					? []
					: await textCodecor.decode(
							form.getFieldValue("ivEncoding"),
							form.getFieldValue("iv")
						);
			const key = await textCodecor.decode(
				form.getFieldValue("keyEncoding"),
				form.getFieldValue("key")
			);

			const outputBytes = await invoke<Uint8Array>("aes_crypto", {
				...form.getFieldsValue(true),
				input,
				iv,
				key,
			});
			const output = await textCodecor.encode(
				form.getFieldValue("outputEncoding"),
				outputBytes
			);

			form.setFieldsValue({ output });
		} catch (err: unknown) {
			form.setFieldsValue({ output: "" });
			console.log(err);
		}
	};

	const renderExtract = (mode: EncryptionMode): React.ReactElement => {
		switch (mode) {
			case EncryptionMode.CBC:
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

			case EncryptionMode.GCM:
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

	return (
		<>
			{notifyContextHodler}
			<Form.Item key="basic">
				<Row justify="space-between" align="middle">
					<Col>
						<Title style={{ margin: 0 }} level={5}>
							Input:
						</Title>
					</Col>
					<Col>
						<Button type="primary" onClick={() => setSettingOpen(true)}>
							settings
						</Button>
					</Col>
					<Col>
						<Space.Compact>
							<OptionButton
								menu={{
									items: [
										{
											label: (
												<div
													onClick={(_) => {
														form.setFieldsValue({
															forEncryption: true,
														});
														form.resetFields([
															"input",
															"output",
															"outputEncoding",
															"inputEncoding",
														]);
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
														const output = form.getFieldValue("output");
														const data: Record<string, unknown> = {
															forEncryption: false,
														};
														if (output && output !== "") {
															data["input"] = output;
														}
														form.setFieldsValue(data);
														form.resetFields([
															"output",
															"outputEncoding",
															"inputEncoding",
														]);
													}}
												>
													decrypt
												</div>
											),
											key: "decrypt",
										},
									],
								}}
								onClick={encryptOrDecrypt}
								size={size}
								children={forEncryption === false ? "decrypt" : "encrypt"}
							></OptionButton>
						</Space.Compact>
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
		</>
	);
};

export default AesInput;
