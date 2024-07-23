import { Button, Card, Col, Form, FormInstance, Row, Typography } from "antd";
import { useForm } from "antd/es/form/Form";
import { Store } from "antd/es/form/interface";
import React, { useEffect, useState } from "react";

import { createStyles } from "antd-style";
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

export type KeyDerivationProps<T> = {
	form: FormInstance<T>;
	initialValues: Store;
};

export type KeyDeriveConfigProps = {
	form: FormInstance;
	generating: boolean;
};

export const derviceKeyConfigHeight = 418;
export const derviceKeyConfigButtonHeight = 0;
export const derviceKeyConfigButtonWidth = 120;

type GeneratorCard = {
	key: string;
	form: FormInstance;
	initValues: RsaKeyDeriveForm | EccKeyDeriveForm | EdwardsDeriveKeyForm;
	config: React.ReactNode;
	component: React.ReactNode;
	encoding: React.ReactNode;
	format: React.ReactNode;
	generate: (form: FormInstance) => Promise<void>;
};

const useStyles = createStyles(({ css }) => ({
	container: css`
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
	keySize: 2048,
};

const eccInitFormValue: EccKeyDeriveForm = {
	privateKey: "",
	publicKey: "",
	pkcsFormat: Pkcs8Format.PKCS8_PEM,
	encoding: TextEncoding.UTF8,
	curveName: EcCuvrname.Secp256k1,
};
const edwardsInitFormValue: EdwardsDeriveKeyForm = {
	privateKey: "",
	publicKey: "",
	pkcsFormat: Pkcs8Format.PKCS8_PEM,
	encoding: TextEncoding.UTF8,
	curveName: EdcurveName.Curve25519,
};

const KeyDerivation = () => {
	const [rsaForm] = useForm<RsaKeyDeriveForm>();
	const [eccForm] = useForm<EccKeyDeriveForm>();
	const [edwardsForm] = useForm<EdwardsDeriveKeyForm>();
	const [activeKey, setActiveKey] = useState<string>("elliptic_curve");
	const { styles } = useStyles();

	const deriveComponents: Record<string, GeneratorCard> = {
		rsa: {
			key: "rsa",
			form: rsaForm,
			initValues: rsaInitFormValue,
			config: <RsaKeySize form={rsaForm} />,
			encoding: <RsaEncoding form={rsaForm} />,
			format: <RsaPkcsFormat form={rsaForm} />,
			component: (
				<KeyDerivationInner form={rsaForm} initialValues={rsaInitFormValue} />
			),
			generate: generateRsaKey,
		},

		elliptic_curve: {
			key: "elliptic_curve",
			form: eccForm,
			initValues: eccInitFormValue,
			config: <EccCurveName form={eccForm} />,
			encoding: <EccEncoding form={eccForm} />,
			format: <EccPkcsFormat form={eccForm} />,
			component: (
				<KeyDerivationInner form={eccForm} initialValues={eccInitFormValue} />
			),
			generate: generateEccKey,
		},
		edwards: {
			key: "edwards",
			form: edwardsForm,
			initValues: edwardsInitFormValue,
			config: <EdwardsCurveName form={edwardsForm} />,
			encoding: <EdwardsEncoding form={edwardsForm} />,
			format: <EdwardsPkcsFormat form={edwardsForm} />,
			component: (
				<KeyDerivationInner
					form={edwardsForm}
					initialValues={edwardsInitFormValue}
				/>
			),
			generate: generateEdwardsKey,
		},
	};

	return (
		<Card
			className={styles.container}
			styles={{
				header: {
					display: "flex",
					alignItems: "space-between",
					borderBottom: "none",
				},
				body: {},
			}}
			activeTabKey={activeKey}
			bordered={false}
			style={{ width: "100%", marginTop: 32, boxShadow: "none" }}
			tabList={Object.keys(deriveComponents).map((key) => {
				return {
					key,
					label: key,
					forceRender: true,
				};
			})}
			tabBarExtraContent={KeyDerivationButton(
				deriveComponents[activeKey].form,
				deriveComponents[activeKey].initValues,
				deriveComponents[activeKey].generate
			)}
			onTabChange={(tab) => {
				setActiveKey(tab);
			}}
			children={deriveComponents[activeKey].component}
			actions={[
				deriveComponents[activeKey].config,
				deriveComponents[activeKey].encoding,
				deriveComponents[activeKey].format,
			]}
		/>
	);
};

const KeyDerivationButton = (
	form: FormInstance,
	initialValues: Store,
	generator: (form: FormInstance) => Promise<void>
) => {
	return (
		<Form form={form} initialValues={initialValues}>
			<Button
				type="primary"
				onClick={async () => {
					await generator(form);
				}}
				children="generate"
			/>
		</Form>
	);
};

const KeyDerivationInner = <T,>({
	form,
	initialValues,
}: {
	form: FormInstance<T>;
	initialValues: Store;
}) => {
	const privateKey = Form.useWatch("privateKey", { form });
	const publicKey = Form.useWatch("publicKey", { form });

	useEffect(() => {
		console.log(initialValues);
	});

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
			<Row>
				<Col span={11}>
					<Card
						title={
							<Typography.Title
								level={5}
								style={{ margin: 0 }}
								children={"PrivateKey"}
							/>
						}
						styles={{
							body: {
								borderRadius: 0,
								whiteSpace: "pre-wrap",
								wordBreak: "break-word",
								color: "#cccccc",
								backgroundColor: "#2c3441",
							},
						}}
					>
						{privateKey}
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
						styles={{
							body: {
								borderRadius: 0,
								whiteSpace: "pre-wrap",
								wordBreak: "break-word",
								color: "#cccccc",
								backgroundColor: "#2c3441",
							},
						}}
					>
						{publicKey}
					</Card>
				</Col>
			</Row>
		</Form>
	);
};

export default KeyDerivation;
