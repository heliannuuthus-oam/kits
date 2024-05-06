import { Col, Form, Row } from "antd";

import AesInput from "../../components/aes/Input";
import { TextEncoding } from "../../components/codec/codec";
import {
	EncryptionMode,
	AesPadding,
	AesSetting,
} from "../../components/aes/Setting";

export type AesEncryptionForm = {
	iv?: string;
	key: string;
	padding: AesPadding;
	mode: EncryptionMode;
	aad?: string;
	input: string;
	output: string;
	keyEncoding: TextEncoding;
	ivEncoding: TextEncoding;
	inputEncoding: TextEncoding;
	outputEncoding: TextEncoding;
	forEncryption: boolean;
};

export const aesComponentSize = "middle";

const AesEncryption = () => {
	const [form] = Form.useForm<AesEncryptionForm>();

	const initialValues: AesEncryptionForm = {
		mode: EncryptionMode.CBC,
		padding: AesPadding.Pkcs7Padding,
		iv: "",
		key: "",
		input: "",
		output: "",
		keyEncoding: TextEncoding.UTF8,
		ivEncoding: TextEncoding.UTF8,
		inputEncoding: TextEncoding.UTF8,
		outputEncoding: TextEncoding.Base64,
		forEncryption: true,
	};

	const onValuesChange = (value: Record<string, unknown>) => {
		if (Object.keys(value).indexOf("mode") !== -1) {
			const updated: Record<string, unknown> = { iv: undefined };
			const mode: string = (value as { mode: string })["mode"];
			if (mode === EncryptionMode.GCM) {
				updated["padding"] = AesPadding.NoPadding;
			}
			form.setFieldsValue(updated);
		}
	};

	return (
		<Form
			form={form}
			onValuesChange={onValuesChange}
			initialValues={initialValues}
			layout="vertical"
			size={aesComponentSize}
			style={{ width: "100%", padding: 24 }}
			validateTrigger="onBlur"
		>
			<Row className="aes" align="middle">
				<AesInput />
				<Col span={12}>
					<AesSetting />
				</Col>
			</Row>
		</Form>
	);
};

export default AesEncryption;
