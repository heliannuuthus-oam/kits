import {
	Card,
	Col,
	Form,
	Input,
	List,
	Radio,
	Row,
	Select,
	SelectProps,
} from "antd";
import { createStyles } from "antd-style";
import { useForm, useWatch } from "antd/es/form/Form";
import { ReactNode, useEffect, useState } from "react";
import {
	fetchJwkeyAlgs,
	fetchJwkeyTypes,
	fetchJwkeyUsages,
	randomId,
} from "../../api/constants";
import { fetchCurveNames } from "../../api/ecc";
import { fetchRsaKeySize } from "../../api/rsa";

type JwkeyForm = {
	keyType: string;
	algorithm: string;
	keyId: string;
	usage: string;
	params: Record<string, unknown> | null;
	operations: string[] | null;
};

const size = "large";

const JwkeyType = ({ onChange }: { onChange?: (value: string) => void }) => {
	const form = Form.useFormInstance<JwkeyForm>();
	const [jwkeyTypes, setJwkeyTypes] = useState<string[]>();

	useEffect(() => {
		randomId().then((id) => {
			form.setFieldValue("keyId", id);
		});
		fetchJwkeyTypes().then((types) => {
			setJwkeyTypes(types);
		});
	}, []);

	return (
		<List
			header={"Key Type"}
			size={size}
			dataSource={jwkeyTypes}
			renderItem={(kt) => (
				<List.Item
					style={{ cursor: "pointer" }}
					onClick={(_) => {
						form.setFieldsValue({ algorithm: "", usage: "" });
						onChange?.(kt);
					}}
					extra={<Radio checked={form.getFieldValue("keyType") === kt} />}
					children={kt}
				/>
			)}
		/>
	);
};

type SettingItem = {
	label: string;
	name: string;
	tips: string | null;
	component: ReactNode;
};
const useStyles = createStyles(({ css }) => ({
	container: css`
		.ant-list-item {
			padding: 16px 0;
		}
	`,
}));

const JwkeySetting = () => {
	const form = Form.useFormInstance<JwkeyForm>();

	const [algs, setAlgs] = useState<SelectProps["options"]>();
	const [usages, setUsages] = useState<SelectProps["options"]>();
	const [bits, setBits] = useState<string[]>();
	const [curves, setCurves] = useState<string[]>();

	const kty = useWatch("keyType", form) ?? "rsa";

	useEffect(() => {
		fetchRsaKeySize().then(setBits);
		fetchCurveNames().then(setCurves);
		fetchJwkeyAlgs(kty).then((algs) => {
			setAlgs(
				algs.map((alg) => {
					return {
						value: alg,
						label: alg,
					};
				})
			);
		});
		fetchJwkeyUsages(kty).then((usages) => {
			setUsages(
				usages.map((usage) => {
					return {
						value: usage,
						label: usage,
					};
				})
			);
		});
	}, [kty]);

	const { styles } = useStyles();

	const renderParams = (kty: string): SettingItem => {
		switch (kty) {
			case "rsa":
				return {
					label: "Bits:",
					name: "bits",
					tips: "",
					component: (
						<Radio.Group
							buttonStyle="solid"
							style={{ display: "flex", justifyContent: "space-between" }}
						>
							{bits?.map((bit) => {
								return (
									<Radio.Button
										style={{ flex: 1, textAlign: "center" }}
										key={bit}
										value={bit}
										children={bit}
									/>
								);
							})}
						</Radio.Group>
					),
				};
			case "ecdsa": {
				return {
					label: "Curve:",
					name: "curve",
					tips: "",
					component: (
						<Radio.Group
							style={{
								display: "flex",
								justifyContent: "space-between",
								flexWrap: "wrap",
								gap: "3px",
							}}
						>
							{curves?.map((curve) => {
								return (
									<Radio.Button
										style={{
											flex: "1 1 calc(33% - 10px)",
											textAlign: "center",
											borderRadius: "0",
											borderInlineStartWidth: "1px",
										}}
										key={curve}
										value={curve}
										children={curve}
									/>
								);
							})}
						</Radio.Group>
					),
				};
			}
			default:
				return {
					label: "",
					name: "",
					tips: "",
					component: <></>,
				};
		}
	};

	const settings: SettingItem[] = [
		{
			label: "Key ID:",
			name: "keyId",
			tips: null,
			component: <Input />,
		},
		{
			label: "Key Algorithm:",
			name: "algorithm",
			tips: "",
			component: <Select options={algs} />,
		},
		{
			label: "Key Usage:",
			name: "usage",
			tips: "",
			component: <Select options={usages} />,
		},
		renderParams(kty),
	];

	return (
		<List
			className={styles.container}
			size={size}
			dataSource={settings}
			renderItem={(item) => {
				return (
					<List.Item
						children={
							<Form.Item
								style={{ width: "100%" }}
								layout="vertical"
								label={item.label}
								name={item.name}
								tooltip=""
								children={item.component}
							/>
						}
					/>
				);
			}}
		/>
	);
};

const JWK = () => {
	let [form] = useForm<JwkeyForm>();

	return (
		<Form form={form} initialValues={{ keyType: "rsa" } as JwkeyForm}>
			<Row gutter={16}>
				<Col span={8}>
					<Card bordered={false} style={{ height: 450 }}>
						<Form.Item name="keyType">
							<JwkeyType />
						</Form.Item>
					</Card>
				</Col>
				<Col span={8}>
					<Card bordered={false} style={{ height: 450 }}>
						<Form.Item noStyle key="jwkey setting">
							<JwkeySetting />
						</Form.Item>
					</Card>
				</Col>
				<Col span={8}>
					<Card bordered={false} style={{ height: 450 }}>
						Card content
					</Card>
				</Col>
			</Row>
		</Form>
	);
};
export default JWK;
