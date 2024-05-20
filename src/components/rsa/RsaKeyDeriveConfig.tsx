import { Form, Select, SelectProps } from "antd";
import { rsaEncodingConverter, rsaPkcsConverter } from "../converter/converter";
import { RsaPkcsSelect } from "./RsaPkcsSelect";
import { RsaEncodingSelect } from "./RsaEncodingSelect";
import {
	KeyDeriveConfigProps,
	derviceKeyConfigButtonHeight,
	derviceKeyConfigButtonWidth,
} from "../../pages/derive";
import { RsaKeyDeriveForm } from ".";

const keySizes: SelectProps["options"] = [2048, 3072, 4096].map((bit) => {
	return {
		value: bit,
		label: <span>{bit}</span>,
	};
});

export const RsaKeyDeriveConfiguration = ({
	generating,
}: KeyDeriveConfigProps) => {
	const form = Form.useFormInstance<RsaKeyDeriveForm>();

	return (
		<>
			<Form.Item name="pkcsFormat" label="pkcs format">
				<RsaPkcsSelect
					converter={rsaPkcsConverter}
					disabled={generating}
					style={{
						minWidth: derviceKeyConfigButtonWidth,
						minHeight: derviceKeyConfigButtonHeight,
					}}
					getInputs={() =>
						form.getFieldsValue(["privateKey", "publicKey", "encoding"])
					}
					setInputs={(value) => {
						form.setFieldsValue(value);
					}}
				/>
			</Form.Item>
			<Form.Item name="encoding" label="encoding">
				<RsaEncodingSelect
					converter={rsaEncodingConverter}
					getInputs={() =>
						form.getFieldsValue(["privateKey", "publicKey", "pkcsFormat"])
					}
					setInputs={(value) => {
						form.setFieldsValue(value);
					}}
					disabled={generating}
					style={{
						minWidth: derviceKeyConfigButtonWidth,
						minHeight: derviceKeyConfigButtonHeight,
					}}
				/>
			</Form.Item>
			<Form.Item name="keySize" label="key size">
				<Select
					disabled={generating}
					options={keySizes}
					style={{
						minWidth: derviceKeyConfigButtonWidth,
						minHeight: derviceKeyConfigButtonHeight,
					}}
				/>
			</Form.Item>
		</>
	);
};
