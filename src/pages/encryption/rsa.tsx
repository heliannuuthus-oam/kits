import { invoke } from "@tauri-apps/api";
import { Button, Col, Form, Row, Select, SelectProps } from "antd";
import TextArea, { TextAreaProps } from "antd/es/input/TextArea";

const DefaultTextArea = ({ style, ...props }: TextAreaProps) => {
	return <TextArea {...props} style={{ resize: "none", ...style }}></TextArea>;
};

enum Digest {
	Sha1 = "sha1",
	Sha256 = "sha256",
	Sha384 = "sha384",
	Sha512 = "sha512",
	Sha3_256 = "sha3-256",
	Sha3_384 = "sha3-384",
	Sha3_512 = "sha3-512",
}

enum Padding {
	Pkcs1_v15 = "pkcs1-v1_5",
	Oaep = "oaep",
}

enum Format {
	Pkcs1_DER = "pkcs1-der",
	Pkcs1_PEM = "pkcs1-pem",
	Pkcs8_PEM = "pkcs8-pem",
	Pkcs8_DER = "pkcs8-der",
}

const digests: SelectProps["options"] = (
	Object.keys(Digest) as Array<keyof typeof Digest>
).map((key) => {
	return { value: Digest[key], label: <span>{Digest[key].toString()}</span> };
});

const paddings: SelectProps["options"] = (
	Object.keys(Padding) as Array<keyof typeof Padding>
).map((key) => {
	return { value: Padding[key], label: <span>{Padding[key].toString()}</span> };
});

const formats: SelectProps["options"] = (
	Object.keys(Format) as Array<keyof typeof Format>
).map((key) => {
	return { value: Format[key], label: <span>{Format[key].toString()}</span> };
});

type RsaEncryptionForm = {
	privateKey: string;
	publicKey: string;
	format: Format;
	padding: Padding;
	digest?: Digest;
	mgfDigest?: Digest;
};

const initialValues: RsaEncryptionForm = {
	privateKey: "",
	publicKey: "",
	format: Format.Pkcs8_PEM,
	padding: Padding.Oaep,
	digest: Digest.Sha256,
	mgfDigest: Digest.Sha256,
};

const RsaEncryption = () => {
	const [form] = Form.useForm<RsaEncryptionForm>();

	const padding = Form.useWatch("padding", form);

	const renderExtract = (padding: Padding) => {
		switch (padding) {
			case Padding.Pkcs1_v15:
				return [<Col span={4}></Col>, <Col span={4}></Col>];
			case Padding.Oaep:
				return [
					<Col span={4}>
						<Form.Item noStyle name="digest">
							<Select options={digests} />
						</Form.Item>
					</Col>,
					<Col span={4}>
						<Form.Item noStyle name="mgfDigest">
							<Select options={digests} />
						</Form.Item>
					</Col>,
				];
		}
	};

	const generate_key = () => {
		invoke("generate_private_rsa", {});
	};

	const encryptOrDecrypt = () => {
		console.log(form.getFieldsValue());
	};

	return (
		<Form
			form={form}
			initialValues={initialValues}
			wrapperCol={{ span: 24 }}
			style={{ padding: 24 }}
		>
			<Form.Item key="key">
				<Row justify="space-between" align="middle">
					<Col span={10}>
						<Form.Item noStyle name="private_key">
							<DefaultTextArea style={{ height: 300 }} />
						</Form.Item>
					</Col>
					<Col span={2}>
						<Button type="primary" style={{ transform: "translateY(-50%)" }}>
							derive
						</Button>
					</Col>
					<Col span={10}>
						<Form.Item noStyle name="public_key">
							<DefaultTextArea style={{ height: 300 }} />
						</Form.Item>
					</Col>
				</Row>
			</Form.Item>

			<Form.Item key="baisc">
				<Row gutter={47} justify="space-between" align="middle">
					{renderExtract(padding)}
					<Col span={4}>
						<Form.Item noStyle name="padding">
							<Select options={paddings} />
						</Form.Item>
					</Col>

					<Col span={4}>
						<Form.Item noStyle name="format">
							<Select options={formats}></Select>
						</Form.Item>
					</Col>
					<Col>
						<Button onClick={generate_key}>generate</Button>
					</Col>
					<Col>
						<Button onClick={encryptOrDecrypt}>encrypt</Button>
					</Col>
				</Row>
			</Form.Item>

			<Form.Item key="input">
				<DefaultTextArea style={{ height: 200 }}></DefaultTextArea>
			</Form.Item>

			<Form.Item key="output">
				<DefaultTextArea style={{ height: 200 }}></DefaultTextArea>
			</Form.Item>
		</Form>
	);
};
export default RsaEncryption;
