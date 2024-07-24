import { Form, Select, SelectProps } from "antd";
import useFormInstance from "antd/es/form/hooks/useFormInstance";
import { useEffect, useState } from "react";
import { fetchEdwardsCuveNames } from "../../api/edwards";
import {
	derviceKeyConfigButtonHeight,
	derviceKeyConfigButtonWidth,
} from "../../pages/derive";

export const EdwardsCurveName = () => {
	const form = useFormInstance();
	const [curveNames, setCurveNames] = useState<SelectProps["options"]>();

	useEffect(() => {
		fetchEdwardsCuveNames().then((curveNames) => {
			form.setFieldsValue({ edwards: { curveName: curveNames[0] } });
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
		<Form.Item noStyle name={["edwards", "curveName"]}>
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
