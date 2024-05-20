import { Form, Select, SelectProps } from "antd";
import {
	edwardPkcsConverter,
	edwardsEncodingConverter,
} from "../converter/converter";
import { EdwardsPkcsSelect } from "./EdwardsPkcsSelect";
import { EdwardsEncodingSelect } from "./EdwardsEncodingSelect";
import {
	KeyDeriveConfigProps,
	derviceKeyConfigButtonHeight,
	derviceKeyConfigButtonWidth,
} from "../../pages/derive";
import { useEffect, useState } from "react";
import { getEdwardsCurveNames } from ".";

export const EdwardsKeyDeriveConfiguration = ({
	form,
	generating,
}: KeyDeriveConfigProps) => {
	const [curveNames, setCurveNames] = useState<SelectProps["options"]>([]);

	useEffect(() => {
		getEdwardsCurveNames().then((curveNames) => {
			setCurveNames(curveNames);
			form.setFieldsValue({ curveName: curveNames?.[0].value });
		});
	}, [getEdwardsCurveNames, setCurveNames]);

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
					options={curveNames}
					style={{
						minWidth: derviceKeyConfigButtonWidth,
						minHeight: derviceKeyConfigButtonHeight,
					}}
				/>
			</Form.Item>
		</>
	);
};
