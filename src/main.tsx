import { ConfigProvider } from "antd";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";

createRoot(document.getElementById("root")!).render(
	<StrictMode>
		<BrowserRouter>
			<ConfigProvider
				theme={{
					token: {
						colorLink: "#000",
						colorPrimaryActive: "#000",
						borderRadius: 5,
					},
				}}
			>
				<App />
			</ConfigProvider>
		</BrowserRouter>
	</StrictMode>
);
