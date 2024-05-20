import {
	Button,
	Col,
	Flex,
	Form,
	FormInstance,
	FormRule,
	Row,
	Tabs,
	Typography,
} from "antd";
import React, { useState } from "react";
import { Store } from "antd/es/form/interface";
import { DefaultTextArea } from "../encryption/rsa";
import { useForm } from "antd/es/form/Form";

import { TextEncoding } from "../../components/codec/codec";
import { RsaKeyDeriveConfiguration } from "../../components/rsa/RsaKeyDeriveConfig";
import { EccKeyDeriveConfiguration } from "../../components/ecc/EccKeyDeriveConfig";
import { EdwardsKeyDeriveConfiguration } from "../../components/edwards/EdwardsKeyDeriveConfig";
import {
	EccKeyDeriveForm,
	deriveEccKey,
	generateEccKey,
} from "../../components/ecc";
import {
	EdwardsDeriveKeyForm,
	deriveEdwardsKey,
	generateEdwardsKey,
} from "../../components/edwards";
import {
	RsaKeyDeriveForm,
	deriveRsaKey,
	generateRsaKey,
} from "../../components/rsa";
import {
	EccCurveName,
	EdwardsCurveName,
	Pkcs8Format,
} from "../../components/converter/converter";
import Collapse from "../../components/Collapse";

export type KeyDerivationProps<T> = {
	form: FormInstance<T>;
	initialValues: Store;
	derivePublicKey: (
		form: FormInstance<T>,
		setGenerating: (generating: boolean) => void
	) => Promise<void>;
	generatePrivateKey: (
		form: FormInstance<T>,
		setGenerating: (generating: boolean) => void
	) => Promise<void>;
	configuration: ({
		form,
		generating,
	}: KeyDeriveConfigProps) => React.JSX.Element;
};

export type KeyDeriveConfigProps = {
	form: FormInstance;
	generating: boolean;
};

export const derviceKeyConfigHeight = 418;
export const derviceKeyConfigButtonHeight = 32;
export const derviceKeyConfigButtonWidth = 120;

const KeyDerivation = () => {
	const [rsaForm] = useForm<RsaKeyDeriveForm>();
	const [eccForm] = useForm<EccKeyDeriveForm>();
	const [edwardsForm] = useForm<EdwardsDeriveKeyForm>();

	const rsaInitFormValue: RsaKeyDeriveForm = {
		privateKey: "",
		publicKey: "",
		pkcsFormat: Pkcs8Format.PKCS8_PEM,
		encoding: TextEncoding.UTF8,
		keySize: 2048,
	};

	const eccInitFormValue: EccKeyDeriveForm = {
		privateKey: "",
		publicKey: "",
		pkcsFormat: Pkcs8Format.PKCS8_PEM,
		encoding: TextEncoding.UTF8,
		curveName: EccCurveName.Secp256k1,
	};
	const edwardsInitFormValue: EdwardsDeriveKeyForm = {
		privateKey: "",
		publicKey: "",
		pkcsFormat: Pkcs8Format.PKCS8_PEM,
		encoding: TextEncoding.UTF8,
		curveName: EdwardsCurveName.Curve25519,
	};

	return (
		<Tabs
			defaultActiveKey="rsa"
			centered
			items={[
				{
					key: "rsa",
					value: (
						<KeyDerivationInner
							form={rsaForm}
							initialValues={rsaInitFormValue}
							derivePublicKey={deriveRsaKey}
							generatePrivateKey={generateRsaKey}
							configuration={RsaKeyDeriveConfiguration}
						/>
					),
				},
				{
					key: "elliptic_curve",
					value: (
						<KeyDerivationInner
							form={eccForm}
							initialValues={eccInitFormValue}
							derivePublicKey={deriveEccKey}
							generatePrivateKey={generateEccKey}
							configuration={EccKeyDeriveConfiguration}
						/>
					),
				},
				{
					key: "edwards",
					value: (
						<KeyDerivationInner
							form={edwardsForm}
							initialValues={edwardsInitFormValue}
							derivePublicKey={deriveEdwardsKey}
							generatePrivateKey={generateEdwardsKey}
							configuration={EdwardsKeyDeriveConfiguration}
						/>
					),
				},
			].map((item) => {
				return {
					key: item.key,
					label: `${item.key}`,
					children: item.value,
				};
			})}
		/>
	);
};

const KeyDerivationInner = <T,>({
	form,
	initialValues,
	derivePublicKey,
	generatePrivateKey,
	configuration,
}: KeyDerivationProps<T>) => {
	const [generating, setGenerating] = useState<boolean>(false);

	const keyValidator: FormRule[] = [
		{ required: true, message: "key is required" },
	];

	return (
		<Form
			form={form}
			initialValues={initialValues}
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
							style={{ height: derviceKeyConfigHeight }}
						/>
					</Form.Item>
				</Col>
				<Col span={6} style={{ padding: "0 15px" }}>
					<Flex justify="space-between" gap={24} vertical>
						<Button
							loading={generating}
							onClick={() => derivePublicKey(form, setGenerating)}
							disabled={generating}
							style={{
								minWidth: derviceKeyConfigButtonWidth,
								minHeight: derviceKeyConfigButtonHeight,
							}}
							type="primary"
						>
							derive
						</Button>
						<Button
							loading={generating}
							type="primary"
							onClick={() => generatePrivateKey(form, setGenerating)}
							style={{
								minWidth: derviceKeyConfigButtonWidth,
								minHeight: derviceKeyConfigButtonHeight,
							}}
						>
							generate
						</Button>
						<Collapse
							items={[
								{
									key: "higher configuration",
									label: "configuration",
									children: configuration({ form, generating }),
								},
							]}
						/>
					</Flex>
				</Col>
				<Col span={9}>
					<Form.Item name="publicKey">
						<DefaultTextArea
							disabled={generating}
							style={{ height: derviceKeyConfigHeight }}
						/>
					</Form.Item>
				</Col>
			</Row>
		</Form>
	);
};

export default KeyDerivation;
