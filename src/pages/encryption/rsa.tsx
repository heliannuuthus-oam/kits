import { invoke } from "@tauri-apps/api";
import { Button, Col, Form, FormInstance, FormRule, Row, Tabs } from "antd";
import TextArea, { TextAreaProps } from "antd/es/input/TextArea";

import { writeText } from "@tauri-apps/api/clipboard";
import useMessage from "antd/es/message/useMessage";
import { useEffect, useState } from "react";
import Collapse from "../../components/Collapse";
import { FormLabel } from "../../components/FormLabel";
import { TextEncoding } from "../../components/codec/codec";
import { RsaPadding } from "../../components/rsa/Padding";

export const DefaultTextArea = ({ style, ...props }: TextAreaProps) => {
	return <TextArea {...props} style={{ resize: "none", ...style }}></TextArea>;
};

enum Padding {
	Pkcs1_v15 = "pkcs1-v1_5",
	Oaep = "oaep",
}

const digestLength: Record<string, number> = {
	sha1: 160,
	sha256: 256,
	sha384: 384,
	sha512: 512,
	"sha3-256": 256,
	"sha3-384": 384,
	"sha3-512": 512,
};

export type RsaEncryptionForm = {
	keySize: number;
	encoding: string;
	format: string;
	pkcs: string;
	privateKey: string;
	publicKey: string;
	padding: string;
	digest: string;
	mgfDigest: string;
	input: string | null;
	inputEncoding: TextEncoding;
	output: string | null;
	outputEncoding: TextEncoding;
	forEncryption: boolean;
};

const initialValues: RsaEncryptionForm = {
	encoding: "",
	format: "",
	pkcs: "",
	keySize: 2048,
	privateKey: "",
	publicKey: "",
	padding: "",
	digest: "",
	mgfDigest: "",
	input: null,
	output: null,

	inputEncoding: TextEncoding.UTF8,
	outputEncoding: TextEncoding.Base64,
	forEncryption: true,
};

type KeyInfo = {
	keySize: number;
	encoding: string;
	format: string;
	pkcs: string;
};

const size = "middle";

const RsaEncryptionInner = ({ form }: { form: FormInstance }) => {
	const [inputMax, setInputMax] = useState<number>(0);

	const [msg, context] = useMessage({
		duration: 4,
		maxCount: 1,
	});

	const forEncryption = Form.useWatch("forEncryption", {
		form,
		preserve: true,
	});

	const activeKeys = Form.useWatch("activeKeys", { form, preserve: true });

	const calcEncryptionMaxLength = (): number => {
		const { padding, keySize, digest } = form.getFieldsValue([
			"padding",
			"keySize",
			"digest",
		]);

		switch (padding) {
			case Padding.Pkcs1_v15:
				return keySize / 8 - 11; // pkcs1_v1-5 padding length
			case Padding.Oaep:
				if (digest) {
					return keySize / 8 - (2 * digestLength[digest]) / 8 - 2;
				}
		}
		return 0;
	};

	useEffect(() => {
		setInputMax(calcEncryptionMaxLength());
	}, [setInputMax, calcEncryptionMaxLength]);

	const keyValidator: FormRule[] = [
		{ required: true, message: "key is required" },
	];

	const inputValidator: FormRule[] = [
		{ required: true, message: "input is required" },
	];
	const parseRsaKey = async (input: string): Promise<KeyInfo> => {
		return await invoke<KeyInfo>("parse_rsa", {
			input,
		});
	};

	const encryptOrDecrypt = async () => {
		try {
			const key = form.getFieldValue(
				!forEncryption ? "privateKey" : "publicKey"
			);
			console.log("key", key);

			const keyInfo = await parseRsaKey(key);
			const output = await invoke<string>("crypto_rsa", {
				data: {
					...form.getFieldsValue(true),
					...keyInfo,
					key: key,
					keyEncoding: keyInfo.encoding,
					keyFormat: keyInfo.format,
				},
			});
			form.setFieldsValue({ output });
			if (output.length > 0 && output.length < 4096) {
				await writeText(output);
				msg.success("copied output");
			}
		} catch (error) {
			console.log(error);
		}
	};

	const renderKey = (data: string) => {
		return (
			<Form.Item key="key" noStyle>
				<Row align={"middle"}>
					<Col span={11}>
						<Form.Item
							key={data}
							name={data}
							labelCol={{ span: 24 }}
							wrapperCol={{ span: 24 }}
							label={
								<FormLabel
									children={data.charAt(0).toUpperCase() + data.slice(1)}
								/>
							}
							rules={keyValidator}
						>
							<DefaultTextArea size={size} showCount style={{ height: 150 }} />
						</Form.Item>
					</Col>

					<Col offset={1} span={11}>
						<Form.Item
							key="input"
							name="input"
							labelCol={{ span: 24 }}
							wrapperCol={{ span: 24 }}
							label={<FormLabel children="Input" />}
							rules={inputValidator}
						>
							<DefaultTextArea
								count={{ max: !forEncryption ? undefined : inputMax }}
								size={size}
								showCount
								style={{ height: 150 }}
							/>
						</Form.Item>
					</Col>
				</Row>
			</Form.Item>
		);
	};

	return (
		<Form
			form={form}
			initialValues={initialValues}
			wrapperCol={{ span: 24 }}
			style={{ padding: "0 24px" }}
			layout="horizontal"
			colon={true}
			validateTrigger="onBlur"
		>
			{context}
			{renderKey(!forEncryption ? "privateKey" : "publicKey")}
			<Form.Item key="padding" noStyle>
				<Row align={"middle"}>
					<Col offset={4} span={16}>
						<Collapse
							onChange={(key) => {
								if (key instanceof Array) {
									form.setFieldsValue({ activeKeys: key });
								} else {
									form.setFieldsValue({ activeKeys: key });
								}
							}}
							activeKey={activeKeys}
							items={[
								{
									key: "rsaPadding",
									label: "rsa padding setting",
									children: <RsaPadding />,
									forceRender: true,
									extra: (
										<Button
											children={!forEncryption ? "decrypt" : "encrypt"}
											onClick={async (e) => {
												e.stopPropagation();
												await encryptOrDecrypt();
											}}
										/>
									),
								},
							]}
						/>
					</Col>
				</Row>
			</Form.Item>

			<Row align={"middle"}>
				<Col offset={5} span={14}>
					<Form.Item
						key="output"
						name="output"
						labelCol={{ span: 24 }}
						wrapperCol={{ span: 24 }}
						label={<FormLabel children="Output" />}
					>
						<DefaultTextArea style={{ height: 249 }} />
					</Form.Item>
				</Col>
			</Row>
		</Form>
	);
};

const RsaEncryption = () => {
	const [form] = Form.useForm<
		RsaEncryptionForm | { activeKeys: string[] | string | null }
	>();
	const inner = <RsaEncryptionInner form={form} />;
	return (
		<Tabs
			centered
			defaultActiveKey={"encryption"}
			onChange={(key) => {
				const forEncryption = key === "encryption";
				if (forEncryption) {
					form.setFieldsValue({
						forEncryption,
						output: null,
						input: null,
						inputEncoding: TextEncoding.UTF8,
						outputEncoding: TextEncoding.Base64,
					});
				} else {
					form.setFieldsValue({
						forEncryption,
						output: null,
						input: null,
						inputEncoding: TextEncoding.Base64,
						outputEncoding: TextEncoding.UTF8,
					});
				}
			}}
			items={[
				{
					label: "encryption",
					key: "encryption",
					children: inner,
					forceRender: true,
				},
				{
					label: "decryption",
					key: "decryption",
					children: inner,
					forceRender: true,
				},
			]}
		/>
	);
};
export default RsaEncryption;
