import { Form, Select } from "antd";
import {
	edwardPkcsConverter,
	edwardsCurveNames,
	edwardsEncodingConverter,
} from "../converter/converter";
import { EdwardsPkcsSelect } from "./EdwardsPkcsSelect";
import { EdwardsEncodingSelect } from "./EdwardsEncodingSelect";
import {
	KeyDeriveConfigProps,
	derviceKeyConfigButtonHeight,
	derviceKeyConfigButtonWidth,
} from "../../pages/derive";
import { EdwardsDeriveKeyForm } from ".";

export const EdwardsKeyDeriveConfiguration = ({
	generating,
}: KeyDeriveConfigProps) => {
	const form = Form.useFormInstance<EdwardsDeriveKeyForm>();

	return (
		<>
			<Form.Item name="pkcsFormat" label="pkcs format">
				<EdwardsPkcsSelect
					converter={edwardPkcsConverter}
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
				<EdwardsEncodingSelect
					converter={edwardsEncodingConverter}
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
					options={edwardsCurveNames}
					style={{
						minWidth: derviceKeyConfigButtonWidth,
						minHeight: derviceKeyConfigButtonHeight,
					}}
				/>
			</Form.Item>
		</>
	);
};
