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
	CurveName,
	Pkcs8Format,
	PkcsFormat,
	PkcsFormats,
	curveNames,
	eccEncodingConverter,
	eccPkcsConverter,
} from "../../components/converter/converter";
import { invoke } from "@tauri-apps/api";
import { EccPkcsSelect } from "../../components/ecc/EccPkcsSelect";
import { EccEncodingSelect } from "../../components/ecc/EccEncodingSelect";

const keyHeight = 418;
const keyButtonHeight = 32;
const keyButtonWidth = 120;

export type EccDeriveKeyForm = {
	privateKey: string;
	publicKey: string;
	pkcsFormat: PkcsFormat;
	encoding: TextEncoding;
	curveName: CurveName;
};

export const EccDeriveKey = () => {
	const [form] = useForm<EccDeriveKeyForm>();
	const [generating, setGenerating] = useState<boolean>(false);
	const initFormValue: EccDeriveKeyForm = {
		privateKey: "",
		publicKey: "",
		pkcsFormat: Pkcs8Format.PKCS8_PEM,
		encoding: TextEncoding.UTF8,
		curveName: CurveName.Secp256k1,
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
			const publicKey = await invoke<string>("derive_ecc", {
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
			const pkcs = PkcsFormats[pkcsFormat];
			pkcs.setEncoding(encoding);
			const [privateKey, publicKey] = await invoke<string[]>("generate_ecc", {
				curveName,
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
												<EccPkcsSelect
													converter={eccPkcsConverter}
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
												<EccEncodingSelect
													converter={eccEncodingConverter}
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
													options={curveNames}
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
export default EccDeriveKey;
