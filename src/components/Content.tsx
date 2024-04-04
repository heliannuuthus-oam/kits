import { Layout } from "antd";
import { BasicProps } from "antd/es/layout/layout";
import routes from "~react-pages";
import { Suspense } from "react";
import { useRoutes } from "react-router-dom";
const { Content: AntdContent } = Layout;

export const Content = ({ ...props }: BasicProps) => {
	return (
		<AntdContent {...props}>
			<Suspense fallback={<p>Loading...</p>}>{useRoutes(routes)}</Suspense>
		</AntdContent>
	);
};
