package com.istrom.po;

import java.util.List;


public class Resource {
	private String id;
	private String type;
	private String name;
	private String path;
	private String descn;
	private List<? extends Role> roles;
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getPath() {
		return path;
	}
	public void setPath(String path) {
		this.path = path;
	}
	public String getDescn() {
		return descn;
	}
	public void setDescn(String descn) {
		this.descn = descn;
	}
	public List<? extends Role> getRoles() {
		return roles;
	}
	public void setRoles(List<? extends Role> roles) {
		this.roles = roles;
	}
	
	
}
