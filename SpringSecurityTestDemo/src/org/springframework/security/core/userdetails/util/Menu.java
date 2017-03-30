package org.springframework.security.core.userdetails.util;

import java.util.ArrayList;
import java.util.List;

public class Menu {

    private String menuid = "";
    private String pId = "0"; //夫级菜单的 id
    private String menuname = "";
    private String url = "";
    private String icon = "icon-nav";
    private String target="";
    private List<Menu> menus = new ArrayList<Menu>();
    //可根据需要添加其他属性
   
    public String getTarget() {
		return target;
	}

	public String getMenuid() {
		return menuid;
	}

	public void setMenuid(String menuid) {
		this.menuid = menuid;
	}

	public String getMenuname() {
		return menuname;
	}

	public void setMenuname(String menuname) {
		this.menuname = menuname;
	}

	public void setTarget(String target) {
		this.target = target;
	}

	public String getPId() {
		return pId;
	}

	public void setPId(String id) {
		pId = id;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getIcon() {
		return icon;
	}

	public void setIcon(String icon) {
		this.icon = icon;
	}

    public List<Menu> getMenus() {
        return menus;
    }

    public void setMenus(List<Menu> menus) {
        this.menus = menus;
    }

    public String getpId() {
        return pId;
    }

    public void setpId(String pId) {
        this.pId = pId;
    }
}