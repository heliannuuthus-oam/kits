import {
	Button,
	Col,
	Collapse,
	Flex,
	Form,
	FormRule,
	Row,
	Select,
	Typography,
} from "antd";
import { DefaultTextArea } from "../encryption/rsa";
import { useState } from "react";
import { TextEncoding } from "../../components/codec/codec";
import { useForm } from "antd/es/form/Form";
import {
	EdwardsCurveName,
	Pkcs8Format,
	PkcsFormat,
	PkcsFormats,
	edwardPkcsConverter,
	edwardsCurveNames,
	edwardsEncodingConverter,
} from "../../components/converter/converter";
import { invoke } from "@tauri-apps/api";
import { EdwardsPkcsSelect } from "../../components/edwards/EdwardsPkcsSelect";
import { EdwardsEncodingSelect } from "../../components/edwards/EdwardsEncodingSelect";

const keyHeight = 418;
const keyButtonHeight = 32;
const keyButtonWidth = 120;

export type EdwardsDeriveKeyForm = {
	privateKey: string;
	publicKey: string;
	pkcsFormat: PkcsFormat;
	encoding: TextEncoding;
	curveName: EdwardsCurveName;
};

export const EdWardsKey = () => {
	const [form] = useForm<EdwardsDeriveKeyForm>();
	const [generating, setGenerating] = useState<boolean>(false);
	const initFormValue: EdwardsDeriveKeyForm = {
		privateKey: "",
		publicKey: "",
		pkcsFormat: Pkcs8Format.PKCS8_PEM,
		encoding: TextEncoding.UTF8,
		curveName: EdwardsCurveName.Curve25519,
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
			const publicKey = await invoke<string>("derive_edwards", {
				key: privateKey,
				...pkcs,
			});
			form.setFieldsValue({ publicKey });
		} catch (error) {
			console.log(error);
		}
	};
	const generatePrivateKey = async () => {
		setGenerating(true);
		try {
			const { curveName, encoding } = form.getFieldsValue([
				"curveName",
				"encoding",
			]);
			const pkcsFormat: PkcsFormat = form.getFieldValue("pkcsFormat");
			console.log(pkcsFormat);

			const pkcs = PkcsFormats[pkcsFormat];
			pkcs.setEncoding(encoding);
			const [privateKey, publicKey] = await invoke<string[]>(
				"generate_edwards",
				{
					curveName,
					...pkcs,
				}
			);

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
			style={{ padding: "24px" }}
			layout="vertical"
			colon={true}
			validateTrigger="onBlur"
		>
			<Row justify="space-between" align="top">
				<Col span={9}>
					<Flex
						align="center"
						justify="space-between"
						style={{ padding: "0 0 24px 0" }}
					>
						<Typography.Title level={5} style={{ margin: 0 }}>
							PrivateKey
						</Typography.Title>
					</Flex>
				</Col>
				<Col offset={4} span={9}>
					<Flex
						align="center"
						justify="space-between"
						style={{ padding: "0 0 24px 0" }}
					>
						<Typography.Title level={5} style={{ margin: 0 }}>
							PublicKey
						</Typography.Title>
					</Flex>
				</Col>
				<Col span={9}>
					<Form.Item name="privateKey" rules={keyValidator}>
						<DefaultTextArea
							disabled={generating}
							style={{ height: keyHeight }}
						/>
					</Form.Item>
				</Col>
				<Col span={6} style={{ padding: "0 15px" }}>
					<Flex justify="space-between" gap={24} vertical>
						<Button
							loading={generating}
							onClick={derivePublicKey}
							disabled={generating}
							style={{ minWidth: keyButtonWidth, minHeight: keyButtonHeight }}
							type="primary"
						>
							derive
						</Button>
						<Button
							loading={generating}
							type="primary"
							onClick={generatePrivateKey}
							style={{ minWidth: keyButtonWidth, minHeight: keyButtonHeight }}
						>
							generate
						</Button>
						<Collapse
							ghost
							items={[
								{
									key: "higher configuration",
									label: "configuration",
									children: (
										<>
											<Form.Item name="pkcsFormat" label="pkcs format">
												<EdwardsPkcsSelect
													converter={edwardPkcsConverter}
													disabled={generating}
													style={{
														minWidth: keyButtonWidth,
														minHeight: keyButtonHeight,
													}}
													getInputs={() =>
														form.getFieldsValue([
															"privateKey",
															"publicKey",
															"encoding",
															"curveName",
														])
													}
													setInputs={form.setFieldsValue}
												/>
											</Form.Item>
											<Form.Item name="encoding" label="encoding">
												<EdwardsEncodingSelect
													converter={edwardsEncodingConverter}
													getInputs={() =>
														form.getFieldsValue([
															"privateKey",
															"publicKey",
															"pkcsFormat",
															"curveName",
														])
													}
													setInputs={form.setFieldsValue}
													disabled={generating}
													style={{
														minWidth: keyButtonWidth,
														minHeight: keyButtonHeight,
													}}
												/>
											</Form.Item>
											<Form.Item name="curveName" label="curve name">
												<Select
													disabled={generating}
													options={edwardsCurveNames}
													style={{
														minWidth: keyButtonWidth,
														minHeight: keyButtonHeight,
													}}
												/>
											</Form.Item>
										</>
									),
								},
							]}
						/>
					</Flex>
				</Col>
				<Col span={9}>
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
export default EdWardsKey;
