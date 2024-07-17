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
	fetchJwkeyOps,
	fetchJwkeyTypes,
	fetchJwkeyUsages,
	randomId,
} from "../../api/constants";
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

	const kty = useWatch("keyType", form) ?? "rsa";

	useEffect(() => {
		fetchRsaKeySize().then(setBits);
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

const JwkeyOperation = ({
	value,
	onChange,
}: {
	value?: string | string[];
	onChange?: (value: string[]) => void;
}) => {
	const form = Form.useFormInstance<JwkeyForm>();
	const [jwkeyOps, setJwkeyOps] = useState<string[]>();

	useEffect(() => {
		fetchJwkeyOps().then(setJwkeyOps);
	}, []);

	return (
		<List
			header={"Key Operations"}
			size={size}
			dataSource={jwkeyOps}
			renderItem={(op) => (
				<List.Item
					style={{ cursor: "pointer" }}
					onClick={(_) => {
						let ops: string[] = [op];
						if (value instanceof Array) {
							let index = value?.indexOf(op);
							if (index > -1) {
								value.splice(index, 1);
							} else {
								value.push(op);
							}
							ops = [...new Set([...value])];
						}
						onChange?.(ops);
					}}
					extra={
						<Radio
							checked={
								(form.getFieldValue("operations") ?? []).indexOf(op) !== -1
							}
						/>
					}
					children={op}
				/>
			)}
		/>
	);
};

const minHeight = 550;

const JWK = () => {
	let [form] = useForm<JwkeyForm>();

	return (
		<Form form={form} initialValues={{ keyType: "rsa" } as JwkeyForm}>
			<Row gutter={16}>
				<Col span={8}>
					<Card bordered={false} style={{ minHeight }}>
						<Form.Item noStyle name="keyType">
							<JwkeyType />
						</Form.Item>
					</Card>
				</Col>
				<Col span={8}>
					<Card bordered={false} style={{ minHeight }}>
						<Form.Item noStyle key="jwkey setting">
							<JwkeySetting />
						</Form.Item>
					</Card>
				</Col>
				<Col span={8}>
					<Card bordered={false} style={{ minHeight }}>
						<Form.Item name="operations" noStyle key="jwkey opration">
							<JwkeyOperation />
						</Form.Item>
					</Card>
				</Col>
			</Row>
		</Form>
	);
};
export default JWK;
