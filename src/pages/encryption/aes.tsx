import { Col, Form, Row } from "antd";
import AesInput from "../../components/aes/Input";
import AesOutput from "../../components/aes/Output";
import { TextEncoding } from "../../components/codec/codec";
import {
	EncryptionMode,
	AesPadding,
	AesSetting,
} from "../../components/aes/Setting";
import { useState } from "react";

export type AesForm = {
	iv?: string;
	key: string;
	padding: AesPadding;
	mode: EncryptionMode;
	aad?: string;
	input: string;
	output: string;
	keyEncoding: TextEncoding;
	ivEncoding: TextEncoding;
	outputEncoding: TextEncoding;
	forEncryption: boolean;
};

export const aesComponentSize = "middle";

const AesEncryption = () => {
	const [form] = Form.useForm<AesForm>();

	const initialValues: AesForm = {
		mode: EncryptionMode.CBC,
		padding: AesPadding.Pkcs7Padding,
		iv: "",
		key: "",
		input: "",
		output: "",
		keyEncoding: TextEncoding.Base64,
		ivEncoding: TextEncoding.Base64,
		outputEncoding: TextEncoding.Base64,
		forEncryption: true,
	};

	const onValuesChange = (value: object) => {
		if (Object.keys(value).indexOf("mode") !== -1) {
			form.setFieldsValue({ key: undefined, iv: undefined });
		}
	};

	const [settingOpen, setSettingOpen] = useState<boolean>(false);

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
			<Row>
				<Col span={12}>
					<AesInput setSettingOpen={setSettingOpen} />
				</Col>
				<Col span={12}>
					<AesOutput />
				</Col>
				<AesSetting
					placement={"left"}
					width={"20%"}
					open={settingOpen}
					onClose={() => setSettingOpen(false)}
				/>
			</Row>
		</Form>
	);
};

export default AesEncryption;
