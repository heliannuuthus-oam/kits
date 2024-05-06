import { DownOutlined } from "@ant-design/icons";
import { Dropdown } from "antd";
import { DropdownButtonProps } from "antd/es/dropdown";

export const OptionButton = ({ ...props }: DropdownButtonProps) => {
	return (
		<Dropdown.Button
			trigger={["hover"]}
			htmlType="submit"
			style={{ margin: 0 }}
			icon={<DownOutlined />}
			{...props}
		/>
	);
};
