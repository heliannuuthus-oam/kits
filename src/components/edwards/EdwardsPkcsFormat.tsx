import { Form } from "antd";
import useFormInstance from "antd/es/form/hooks/useFormInstance";
import { forwardRef } from "react";
import {
	derviceKeyConfigButtonHeight,
	derviceKeyConfigButtonWidth,
} from "../../pages/derive";
import {
	ConvertRef,
	ConvertSelectProps,
	EccFromat,
	Pkcs8Format,
	PkcsEncodingProps,
	edwardPkcsConverter,
} from "../converter/converter";
import { PkcsFormatSelect } from "../converter/PkcsFormatSelect";

export const EdwardsPkcsSelect = forwardRef<
	ConvertRef,
	ConvertSelectProps<EccFromat, PkcsEncodingProps>
>(
	(
		{
			converter = edwardPkcsConverter,
			getInputs,
			setInputs,
			onChange,
			value,
			...props
		},
		ref
	) => {
		return (
			<PkcsFormatSelect
				ref={ref}
				converter={converter}
				getInputs={getInputs}
				setInputs={setInputs}
				value={value}
				onChange={onChange}
				defaultValue={Pkcs8Format.PKCS8_PEM}
				options={[
					{ value: Pkcs8Format.PKCS8_PEM, label: <span>pkcs8-pem</span> },
					{ value: Pkcs8Format.PKCS8_DER, label: <span>pkcs8-der</span> },
				]}
				{...props}
			/>
		);
	}
);

export const EdwardsPkcsFormat = () => {
	const form = useFormInstance();
	return (
		<Form.Item noStyle name={["edwards", "pkcsFormat"]}>
			<EdwardsPkcsSelect
				converter={edwardPkcsConverter}
				style={{
					minWidth: derviceKeyConfigButtonWidth,
					minHeight: derviceKeyConfigButtonHeight,
				}}
				getInputs={() => form.getFieldValue("edwards")}
				setInputs={(edwards) => {
					form.setFieldsValue({ edwards });
				}}
			/>
		</Form.Item>
	);
};
