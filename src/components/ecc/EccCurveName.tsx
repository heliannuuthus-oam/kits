import { Form, FormInstance, Select, SelectProps } from "antd";
import { useEffect, useState } from "react";
import { EccKeyDeriveForm } from ".";
import { fetchCurveNames } from "../../api/ecc";
import {
	derviceKeyConfigButtonHeight,
	derviceKeyConfigButtonWidth,
} from "../../pages/derive";

export const EccCurveName = ({
	form,
}: {
	form: FormInstance<EccKeyDeriveForm>;
}) => {
	const [curveNames, setCurveNames] = useState<SelectProps["options"]>();

	useEffect(() => {
		fetchCurveNames().then((curveNames) => {
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
	}, [fetchCurveNames]);

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
