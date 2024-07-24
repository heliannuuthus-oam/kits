import { Form, Select, SelectProps } from "antd";
import useFormInstance from "antd/es/form/hooks/useFormInstance";
import { useEffect, useState } from "react";
import { fetchRsaKeySize } from "../../api/rsa";

export const RsaKeySize = () => {
	const [keySizes, setKeySizes] = useState<SelectProps["options"]>();

	const form = useFormInstance();

	useEffect(() => {
		fetchRsaKeySize().then((keySizes) => {
			form.setFieldsValue({ rsa: { keySize: keySizes[0] } });
			setKeySizes(
				keySizes.map((keySize) => {
					return {
						value: keySize,
						label: keySize,
					};
				})
			);
		});
	}, [fetchRsaKeySize]);

	return (
		<Form.Item noStyle name={["rsa", "keySize"]}>
			<Select options={keySizes} style={{ minWidth: 120 }} />
		</Form.Item>
	);
};
