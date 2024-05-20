import { Form, Select } from "antd";
import { EccPkcsSelect } from "./EccPkcsSelect";
import {
	eccCurveNames,
	eccEncodingConverter,
	eccPkcsConverter,
} from "../converter/converter";
import { EccEncodingSelect } from "./EccEncodingSelect";
import {
	KeyDeriveConfigProps,
	derviceKeyConfigButtonHeight,
	derviceKeyConfigButtonWidth,
} from "../../pages/derive";
import { EccKeyDeriveForm } from ".";

export const EccKeyDeriveConfiguration = ({
	generating,
}: KeyDeriveConfigProps) => {
	const form = Form.useFormInstance<EccKeyDeriveForm>();

	return (
		<>
			<Form.Item name="pkcsFormat" label="pkcs format">
				<EccPkcsSelect
					converter={eccPkcsConverter}
					disabled={generating}
					style={{
						minWidth: derviceKeyConfigButtonWidth,
						minHeight: derviceKeyConfigButtonHeight,
					}}
					getInputs={() =>
						form.getFieldsValue([
							"privateKey",
							"publicKey",
							"encoding",
							"curveName",
						])
					}
					setInputs={(value) => {
						form.setFieldsValue(value);
					}}
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
			<Form.Item name="curveName" label="curve name">
				<Select
					disabled={generating}
					options={eccCurveNames}
					style={{
						minWidth: derviceKeyConfigButtonWidth,
						minHeight: derviceKeyConfigButtonHeight,
					}}
				/>
			</Form.Item>
		</>
	);
};
