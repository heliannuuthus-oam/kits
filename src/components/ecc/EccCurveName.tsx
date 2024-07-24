import { Form, Select, SelectProps } from "antd";
import useFormInstance from "antd/es/form/hooks/useFormInstance";
import { useEffect, useState } from "react";
import { fetchCurveNames } from "../../api/ecc";
import {
	derviceKeyConfigButtonHeight,
	derviceKeyConfigButtonWidth,
} from "../../pages/derive";

export const EccCurveName = () => {
	const [curveNames, setCurveNames] = useState<SelectProps["options"]>();
	const form = useFormInstance();

	useEffect(() => {
		fetchCurveNames().then((curveNames) => {
			form.setFieldsValue({ elliptic_curve: { curveName: curveNames[0] } });
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
		<Form.Item noStyle name={["elliptic_curve", "curveName"]}>
			<Select
				options={curveNames}
				style={{
					minWidth: derviceKeyConfigButtonWidth,
					minHeight: derviceKeyConfigButtonHeight,
				}}
			/>
		</Form.Item>
	);
};
