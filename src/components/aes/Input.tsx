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
import { TextEncoding } from "../codec/codec";
import { EncryptionMode } from "./Setting";
import { AesEncryptionForm } from "../../pages/encryption/aes";
import useFormInstance from "antd/es/form/hooks/useFormInstance";
import { useWatch } from "antd/es/form/Form";

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

const AesInput = () => {
	const form = Form.useFormInstance<AesEncryptionForm>();
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

	const textareaValidator: FormRule[] = [
		{ required: true, message: "content is required" },
		{
			min: 1,
			message: "message must not be empty",
		},
	];

	const generateKey = async () => {
		try {
			const key = await invoke<string>("generate_aes", {
				keySize,
				encoding: form.getFieldValue("keyEncoding"),
			});

			form.setFieldsValue({ key });
		} catch (err: unknown) {
			notify(err);
		}
	};

	const renderExtract = (mode: EncryptionMode): React.ReactElement => {
		switch (mode) {
			case EncryptionMode.CBC:
				return (
					<Form.Item key="cbc_iv">
						<IvInput />
					</Form.Item>
				);

			case EncryptionMode.GCM:
				return (
					<>
						<Form.Item key="gcm_iv" hasFeedback>
							<IvInput />
						</Form.Item>
						<Form.Item key="gcm_aad" name="aad">
							<InputTitle content="Aad" />
							<Input placeholder="input aad" />
						</Form.Item>
					</>
				);
			default:
				return <></>;
		}
	};

	return (
		<Col span={12}>
			{notifyContextHodler}
			<Form.Item key="key">
				<InputTitle content="Key" />
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
						generate
					</Button>
				</Space.Compact>
			</Form.Item>
			{renderExtract(mode)}
			<InputTitle content="Input" />
			<Form.Item key="input">
				<div
					style={{
						height: 200,
					}}
				>
					<Form.Item noStyle name="input" rules={textareaValidator}>
						<TextArea style={{ height: "100%", resize: "none" }} />
					</Form.Item>
				</div>
			</Form.Item>
			<InputTitle content="Output" />
			<Form.Item key="output">
				<div
					style={{
						height: 200,
					}}
				>
					<Form.Item noStyle name="output">
						<TextArea style={{ height: "100%", resize: "none" }} />
					</Form.Item>
				</div>
			</Form.Item>
		</Col>
	);
};

const IvInput = () => {
	const form = useFormInstance<AesEncryptionForm>();
	const mode = useWatch("mode", form);

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

	const generateIv = async () => {
		try {
			const iv = await invoke<string>("generate_iv", {
				size: mode === EncryptionMode.CBC ? 16 : 12,
				encoding: form.getFieldValue("ivEncoding"),
			});

			form.setFieldsValue({ iv });
		} catch (err: unknown) {
			console.log(err);
		}
	};

	return (
		<>
			<InputTitle content="Iv" />
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
					generate
				</Button>
			</Space.Compact>
		</>
	);
};

const InputTitle = ({ content }: { content: string }) => {
	return (
		<Row justify="space-between" align="middle">
			<Col>
				<Title style={{ margin: "0 0 12px 0" }} level={5}>
					{content}:
				</Title>
			</Col>
		</Row>
	);
};

export default AesInput;
