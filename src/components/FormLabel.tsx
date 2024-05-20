import { Typography } from "antd";
import { TitleProps } from "antd/es/typography/Title";

const { Title } = Typography;

export const FormLabel = ({ ...props }: TitleProps) => {
	return <Title {...props} style={{ margin: 0 }} level={5} />;
};
