import {
	Button,
	Col,
	Form,
	FormRule,
	Row,
	Select,
	SelectProps,
	Tabs,
} from "antd";
import TextArea, { TextAreaProps } from "antd/es/input/TextArea";

import { invoke } from "@tauri-apps/api";
import { FormInstance, useWatch } from "antd/es/form/Form";
import { useEffect, useState } from "react";
import Collapse from "../../components/Collapse";
import { FormLabel } from "../../components/FormLabel";
import { TextEncoding } from "../../components/codec/codec";
import { getEccCurveNames } from "../../components/ecc";
import { EciesEncryptionForm, EciesKdf } from "../../components/ecc/kdf";
import { writeText } from "@tauri-apps/api/clipboard";
import useMessage from "antd/es/message/useMessage";

const DefaultTextArea = ({ style, ...props }: TextAreaProps) => {
	return <TextArea {...props} style={{ resize: "none", ...style }}></TextArea>;
};

const initialValues: EciesEncryptionForm = {
	curveName: "",
	privateKey: "",
	publicKey: "",
	input: null,
	inputEncoding: TextEncoding.UTF8,
	output: null,
	outputEncoding: TextEncoding.Base64,
	kdf: "",
	kdfDigest: "",
	salt: null,
	saltEncoding: TextEncoding.UTF8,
	info: null,
	infoEncoding: TextEncoding.UTF8,
	encryptionAlg: "",
	forEncryption: true,
};

type KeyInfo = {
	curveName: string;
	encoding: string;
	format: string;
	pkcs: string;
};

const size = "middle";
const EciesInner = ({ form }: { form: FormInstance }) => {
	const [curveNames, setCurveNames] = useState<SelectProps["options"]>([]);
	const [msg, context] = useMessage({
		duration: 4,
		maxCount: 1,
	});

	useEffect(() => {
		getEccCurveNames().then((curveNames) => {
			setCurveNames(curveNames);
			form.setFieldsValue({ curveName: curveNames?.[0].value });
		});
	}, [getEccCurveNames, setCurveNames, form]);

	const keyValidator: FormRule[] = [
		{ required: true, message: "key is required" },
	];
	const inputValidator: FormRule[] = [
		{ required: true, message: "input is required" },
	];
	const forEncryption = useWatch("forEncryption", { form, preserve: true });
	const activeKeys = useWatch("activeKeys", { form, preserve: true });

	const parseEccKey = async (input: string): Promise<KeyInfo> => {
		return await invoke<KeyInfo>("parse_ecc", {
			input,
		});
	};

	const encryptOrDecrypt = async () => {
		try {
			const key = form.getFieldValue(
				!forEncryption ? "privateKey" : "publicKey"
			);
			console.log(form.getFieldsValue(true));
			const keyInfo = await parseEccKey(key);
			const output = await invoke<string>("ecies", {
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
							<DefaultTextArea size={size} showCount style={{ height: 150 }} />
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
			style={{ padding: "0 24px" }}
			layout="horizontal"
			colon={true}
			validateTrigger="onBlur"
		>
			{context}
			{renderKey(!forEncryption ? "privateKey" : "publicKey")}
			<Row align={"middle"}>
				<Col offset={9} span={6}>
					<Form.Item name="curveName">
						<Select options={curveNames} />
					</Form.Item>
				</Col>
			</Row>
			<Form.Item key="kdf" noStyle>
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
									key: "kdfConfig",
									label: "key derive function configuration",
									children: <EciesKdf />,
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

const EciesEncryption = () => {
	const [form] = Form.useForm<EciesEncryptionForm>();
	const inner = <EciesInner form={form} />;
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
export default EciesEncryption;
