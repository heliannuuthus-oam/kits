import { Form, FormInstance, Select, SelectProps } from "antd";
import { useEffect, useState } from "react";
import { EdwardsDeriveKeyForm } from ".";
import { fetchEdwardsCuveNames } from "../../api/edwards";
import {
	derviceKeyConfigButtonHeight,
	derviceKeyConfigButtonWidth,
} from "../../pages/derive";

export const EdwardsCurveName = ({
	form,
}: {
	form: FormInstance<EdwardsDeriveKeyForm>;
}) => {
	const [curveNames, setCurveNames] = useState<SelectProps["options"]>();

	useEffect(() => {
		fetchEdwardsCuveNames().then((curveNames) => {
			form.setFieldsValue({ curveName: curveNames[0] });
			setCurveNames(
				curveNames.map((curveName) => {
					return {
						value: curveName,
						label: curveName,
					};
				})
			);
		});
	}, [fetchEdwardsCuveNames]);

	return (
		<Form form={form}>
			<Form.Item noStyle name="curveName">
				<Select
					options={curveNames}
					style={{
						minWidth: derviceKeyConfigButtonWidth,
						minHeight: derviceKeyConfigButtonHeight,
					}}
				/>
			</Form.Item>
		</Form>
	);
};
