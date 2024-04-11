import { App, AppProps, ConfigProvider } from "antd";
import { Suspense } from "react";
import { useRoutes } from "react-router-dom";
import routes from "~react-pages";

export const Content = ({ ...props }: AppProps) => {
	return (
		<ConfigProvider
			theme={{
				token: {
					colorLink: "#000",
					colorPrimaryActive: "#000",
				},
				components: {
					Layout: {
						headerHeight: 64,
						headerBg: "#fff",
						bodyBg: "#fff",
					},
					Space: {
						colorBgBase: "#fff",
						colorBgContainer: "#fff",
					},
				},
			}}
		>
			<App {...props}>
				<Suspense fallback={<p>Loading...</p>}>{useRoutes(routes)}</Suspense>
			</App>
		</ConfigProvider>
	);
};
