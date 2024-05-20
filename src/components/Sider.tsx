import { ConfigProvider, Layout, Menu, MenuProps, SiderProps } from "antd";
import { useEffect, useState } from "react";
import { Link, RouteObject, useLocation } from "react-router-dom";
import routes from "virtual:generated-pages-react";

const { Sider: AntdSider } = Layout;

type MenuItem = Required<MenuProps>["items"][number];

function Item(
	label: React.ReactNode,
	key: React.Key,
	icon?: React.ReactNode,
	children?: MenuItem[],
	type?: "group"
): MenuItem {
	return children && children.length > 0
		? {
				key,
				icon,
				children,
				label,
				type,
			}
		: ({
				key,
				icon,
				label,
				type,
			} as MenuItem);
}

const chidren = (ros: RouteObject[], parent: string | undefined) => {
	return ros
		.filter((ro) => ro.path !== "")
		.map((ro: RouteObject) => {
			return Item(
				<Link to={parent + "/" + ro.path}>{ro.path}</Link>,
				parent + "/" + ro.path || 2
			);
		});
};

const menuItems: MenuProps["items"] = routes
	.filter((ro) => ro.path !== "/")
	.map((ro: RouteObject) => {
		return Item(
			<Link to={ro.path || "/"}>{ro.path}</Link>,
			ro.path || 1,
			null,
			ro.children && ro.children.length > 0
				? chidren(ro.children, ro.path)
				: undefined
		);
	});

export const Sider = ({ ...props }: SiderProps) => {
	const [selectedKeys, setSelectedKeys] = useState<string[]>([]);
	const [openKeys, setOpenKeys] = useState<string[]>([]);
	const { pathname } = useLocation();

	useEffect(() => {
		console.log(menuItems);
		const path = pathname.substring(1);
		const leaf = path.lastIndexOf("/");
		const parent = path.substring(
			0,
			leaf === -1 || leaf === 0 ? pathname.length : leaf
		);
		setOpenKeys([parent]);
		setSelectedKeys([path]);
	}, [pathname]);

	return (
		<ConfigProvider
			theme={{
				token: {
					colorLink: "#000",
					colorPrimaryActive: "#000",
				},
				components: {
					Menu: {
						itemActiveBg: "rgba(0, 0, 0, 0.06)",
						itemSelectedBg: "rgba(0, 0, 0, 0.06)",
					},
				},
			}}
		>
			<AntdSider {...props}>
				<Menu
					mode="inline"
					style={{ width: 256, height: "100%" }}
					selectedKeys={selectedKeys}
					openKeys={openKeys}
					items={menuItems}
					onOpenChange={(keys: string[]) => {
						setOpenKeys(keys);
					}}
				/>
			</AntdSider>
		</ConfigProvider>
	);
};
