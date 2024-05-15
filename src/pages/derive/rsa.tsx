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
import { useState } from "react";
import { TextEncoding } from "../../components/codec/codec";
import { useForm } from "antd/es/form/Form";
import {
	Pkcs8Format,
	PkcsFormat,
	PkcsFormats,
	rsaEncodingConverter,
	rsaPkcsConverter,
} from "../../components/converter/converter";
import { invoke } from "@tauri-apps/api";
import { RsaPkcsSelect } from "../../components/rsa/RsaPkcsSelect";
import { RsaEncodingSelect } from "../../components/rsa/RsaEncodingSelect";

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
	pkcsFormat: PkcsFormat;
	encoding: TextEncoding;
	keySize: number;
};

const RsaDeriveKey = () => {
	const [form] = useForm<RsaDeriveKeyForm>();
	const [generating, setGenerating] = useState<boolean>(false);
	const initFormValue: RsaDeriveKeyForm = {
		privateKey: "",
		publicKey: "",
		pkcsFormat: Pkcs8Format.PKCS8_PEM,
		encoding: TextEncoding.UTF8,
		keySize: 2048,
	};

	const keyValidator: FormRule[] = [
		{ required: true, message: "key is required" },
	];

	const derivePublicKey = async () => {
		try {
			const { privateKey, pkcsFormat, encoding } = form.getFieldsValue([
				"privateKey",
				"pkcsFormat",
				"encoding",
			]);
			const pkcs = PkcsFormats[pkcsFormat as PkcsFormat];
			pkcs.setEncoding(encoding as TextEncoding);
			return await invoke<Uint8Array>("derive_rsa", {
				key: privateKey,
				...pkcs,
			});
		} catch (error) {
			console.log(error);
		}
	};
	const generatePrivateKey = async () => {
		setGenerating(true);
		try {
			const { keySize, encoding } = form.getFieldsValue([
				"keySize",
				"encoding",
			]);
			console.log(form.getFieldsValue(true));

			const pkcsFormat: PkcsFormat = form.getFieldValue("pkcsFormat");
			console.log(pkcsFormat);

			const pkcs = PkcsFormats[pkcsFormat];
			pkcs.setEncoding(encoding);
			const [privateKey, publicKey] = await invoke<string[]>("generate_rsa", {
				keySize,
				...pkcs,
			});

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
						<Form.Item name="pkcsFormat" label="pkcsFormat">
							<RsaPkcsSelect
								converter={rsaPkcsConverter}
								disabled={generating}
								style={{
									minWidth: keyButtonWidth,
									minHeight: keyButtonHeight,
								}}
								getInputs={() =>
									form.getFieldsValue(["privateKey", "publicKey", "encoding"])
								}
								setInputs={form.setFieldsValue}
							/>
						</Form.Item>
						<Form.Item name="encoding" label="encoding">
							<RsaEncodingSelect
								converter={rsaEncodingConverter}
								getInputs={() =>
									form.getFieldsValue(["privateKey", "publicKey", "pkcsFormat"])
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
