import { Button, Card, Col, Form, FormInstance, Row, Typography } from "antd";
import React, { useEffect, useState } from "react";

import { writeText } from "@tauri-apps/api/clipboard";
import { createStyles } from "antd-style";
import { CardTabListType } from "antd/es/card";
import { useForm } from "antd/es/form/Form";
import useFormInstance from "antd/es/form/hooks/useFormInstance";
import TextArea from "antd/es/input/TextArea";
import useMessage from "antd/es/message/useMessage";
import { TextEncoding } from "../../components/codec/codec";
import {
	EccCurveName as EcCuvrname,
	EdwardsCurveName as EdcurveName,
	Pkcs8Format,
} from "../../components/converter/converter";
import { EccKeyDeriveForm, generateEccKey } from "../../components/ecc";
import { EccCurveName } from "../../components/ecc/EccCurveName";
import { EccEncoding } from "../../components/ecc/EccEncoding";
import { EccPkcsFormat } from "../../components/ecc/EccPkcsFormat";
import {
	EdwardsDeriveKeyForm,
	generateEdwardsKey,
} from "../../components/edwards";
import { EdwardsCurveName } from "../../components/edwards/EdwardsCurveName";
import { EdwardsEncoding } from "../../components/edwards/EdwardsEncoding";
import { EdwardsPkcsFormat } from "../../components/edwards/EdwardsPkcsFormat";
import { RsaKeyDeriveForm, generateRsaKey } from "../../components/rsa";
import { RsaEncoding } from "../../components/rsa/RsaEncoding";
import { RsaKeySize } from "../../components/rsa/RsaKeySize";
import { RsaPkcsFormat } from "../../components/rsa/RsaPkcsFormat";

export const derviceKeyConfigHeight = 418;
export const derviceKeyConfigButtonHeight = 0;
export const derviceKeyConfigButtonWidth = 120;

type GeneratorCard = {
	key: string;
	initValues: RsaKeyDeriveForm | EccKeyDeriveForm | EdwardsDeriveKeyForm;
	config: React.ReactNode;
	component: React.ReactNode;
	encoding: React.ReactNode;
	format: React.ReactNode;
	generate: (form: FormInstance) => Promise<void>;
};

type DeriveKeyForm = {
	rsa: RsaKeyDeriveForm;
	elliptic_curve: EccKeyDeriveForm;
	edwards: EdwardsDeriveKeyForm;
};

const useStyles = createStyles(({ css }) => ({
	container: css`
		.ant-tabs-nav:before {
			border-bottom: 0;
		}
		.ant-tabs-nav-wrap {
			display: flex;
			flex-direction: column;
			align-items: center;
		}
	`,
}));

const rsaInitFormValue: RsaKeyDeriveForm = {
	privateKey: "",
	publicKey: "",
	pkcsFormat: Pkcs8Format.PKCS8_PEM,
	encoding: TextEncoding.UTF8,
	keySize: "2048",
};

const eccInitFormValue: EccKeyDeriveForm = {
	privateKey: "",
	publicKey: "",
	pkcsFormat: Pkcs8Format.PKCS8_PEM,
	encoding: TextEncoding.UTF8,
	curveName: EcCuvrname.NIST_P256,
};
const edwardsInitFormValue: EdwardsDeriveKeyForm = {
	privateKey: "",
	publicKey: "",
	pkcsFormat: Pkcs8Format.PKCS8_PEM,
	encoding: TextEncoding.UTF8,
	curveName: EdcurveName.Curve25519,
};

const initialValues: DeriveKeyForm = {
	rsa: rsaInitFormValue,
	elliptic_curve: eccInitFormValue,
	edwards: edwardsInitFormValue,
};

const KeyDerivation = () => {
	const [form] = useForm<DeriveKeyForm>();
	const [activeKey, setActiveKey] = useState<string>("elliptic_curve");
	const { styles } = useStyles();

	const deriveComponents: Record<string, GeneratorCard> = {
		rsa: {
			key: "rsa",
			initValues: rsaInitFormValue,
			config: <RsaKeySize />,
			encoding: <RsaEncoding />,
			format: <RsaPkcsFormat />,
			component: <KeyDerivationInner activeKey="rsa" />,
			generate: generateRsaKey,
		},

		elliptic_curve: {
			key: "elliptic_curve",
			initValues: eccInitFormValue,
			config: <EccCurveName />,
			encoding: <EccEncoding />,
			format: <EccPkcsFormat />,
			component: <KeyDerivationInner activeKey="elliptic_curve" />,
			generate: generateEccKey,
		},
		edwards: {
			key: "edwards",
			initValues: edwardsInitFormValue,
			config: <EdwardsCurveName />,
			encoding: <EdwardsEncoding />,
			format: <EdwardsPkcsFormat />,
			component: <KeyDerivationInner activeKey="edwards" />,
			generate: generateEdwardsKey,
		},
	};

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
			<Card
				className={styles.container}
				styles={{
					header: {
						display: "flex",
						alignItems: "space-between",
						borderBottom: "none",
					},
					body: {},
					actions: {
						borderTop: 0,
					},
				}}
				activeTabKey={activeKey}
				bordered={false}
				style={{ width: "100%", marginTop: 32, boxShadow: "none" }}
				tabList={Object.entries(deriveComponents).map((key) => {
					return {
						key: key[0],
						label: key[0],
						forceRender: true,
						children: key[1].component,
					} as CardTabListType;
				})}
				tabBarExtraContent={
					<Button
						onClick={async () => {
							await deriveComponents[activeKey].generate(form);
						}}
						type="primary"
						children="generate"
					/>
				}
				onTabChange={(tab) => {
					setActiveKey(tab);
				}}
				actions={[
					deriveComponents[activeKey].config,
					deriveComponents[activeKey].encoding,
					deriveComponents[activeKey].format,
				]}
			/>
		</Form>
	);
};

const cardStyles: {
	header?: React.CSSProperties;
	body?: React.CSSProperties;
	extra?: React.CSSProperties;
	title?: React.CSSProperties;
	actions?: React.CSSProperties;
	cover?: React.CSSProperties;
} = {
	title: {
		padding: 0,
	},
	header: {
		display: "flex",
	},
	extra: {
		padding: 0,
	},
	body: {
		borderRadius: 0,
		whiteSpace: "pre-wrap",
		wordBreak: "break-word",
		color: "#cccccc",
		backgroundColor: "#2c3441",
		minHeight: 420,
		maxHeight: 420,
		overflow: "auto",
	},
};
const KeyDerivationInner = ({ activeKey }: { activeKey: string }) => {
	const form = useFormInstance();

	useEffect(() => {
		switch (activeKey) {
			case "rsa":
				generateRsaKey(form).then();
				break;
			case "elliptic_curve":
				generateEccKey(form).then();
				break;
			case "edwards":
				generateEdwardsKey(form).then();
				break;
		}
	}, [generateRsaKey, generateEccKey, generateEdwardsKey]);

	const [msgApi, context] = useMessage({
		duration: 4,
		maxCount: 1,
	});

	return (
		<Row>
			{context}
			<Col span={11}>
				<Card
					title={
						<Typography.Title
							level={5}
							style={{ margin: 0 }}
							children={"PrivateKey"}
						/>
					}
					extra={
						<Button
							type="dashed"
							children="copy"
							onClick={async () => {
								const { privateKey } = form.getFieldValue(activeKey);
								await writeText(privateKey);
								msgApi.success("private key copied");
							}}
						/>
					}
					styles={cardStyles}
				>
					<Form.Item name={[activeKey, "privateKey"]} noStyle>
						<TextArea
							autoSize={{ minRows: 16, maxRows: 16 }}
							variant="borderless"
							style={{
								color: "#cccccc",
								backgroundColor: "#2c3441",
								resize: "none",
							}}
						/>
					</Form.Item>
				</Card>
			</Col>
			<Col offset={1} span={11}>
				<Card
					title={
						<Typography.Title
							level={5}
							style={{ margin: 0 }}
							children={"PublicKey"}
						/>
					}
					extra={
						<Button
							type="dashed"
							onClick={async () => {
								const { publicKey } = form.getFieldValue(activeKey);
								await writeText(publicKey);
								msgApi.success("public key copied");
							}}
							children="copy"
						/>
					}
					styles={cardStyles}
				>
					<Form.Item name={[activeKey, "publicKey"]} noStyle>
						<TextArea
							autoSize={{ minRows: 16, maxRows: 16 }}
							variant="borderless"
							style={{
								color: "#cccccc",
								backgroundColor: "#2c3441",
								resize: "none",
							}}
						/>
					</Form.Item>
				</Card>
			</Col>
		</Row>
	);
};

export default KeyDerivation;
