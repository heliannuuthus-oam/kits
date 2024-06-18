import { Typography } from "antd";

const { Title } = Typography;

export const FormLabel = ({ content }: { content: string }) => {
	return (
		<Title style={{ margin: "0" }} level={5}>
			{content}:
		</Title>
	);
};
