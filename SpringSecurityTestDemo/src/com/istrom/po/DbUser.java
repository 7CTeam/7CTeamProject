package com.istrom.po;

import java.util.Collection;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class DbUser {
	private String id;
	private String username;
	private String password;
	private String status;
	private String descn;
	private String email;
	private String company_title;
	private String duty;
	private String realname;
	private String mobile;
	private String logtime;
	private String department;
	private String reporter;
	private Collection<SimpleGrantedAuthority> rolelist;
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getStatus() {
		return status;
	}
	public void setStatus(String status) {
		this.status = status;
	}
	public String getDescn() {
		return descn;
	}
	public void setDescn(String descn) {
		this.descn = descn;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getCompany_title() {
		return company_title;
	}
	public void setCompany_title(String company_title) {
		this.company_title = company_title;
	}
	public String getDuty() {
		return duty;
	}
	public void setDuty(String duty) {
		this.duty = duty;
	}
	public String getRealname() {
		return realname;
	}
	public void setRealname(String realname) {
		this.realname = realname;
	}
	public String getMobile() {
		return mobile;
	}
	public void setMobile(String mobile) {
		this.mobile = mobile;
	}
	public String getLogtime() {
		return logtime;
	}
	public void setLogtime(String logtime) {
		this.logtime = logtime;
	}
	public String getDepartment() {
		return department;
	}
	public void setDepartment(String department) {
		this.department = department;
	}
	public String getReporter() {
		return reporter;
	}
	public void setReporter(String reporter) {
		this.reporter = reporter;
	}
	public Collection<SimpleGrantedAuthority> getRolelist() {
		return rolelist;
	}
	public void setRolelist(Collection<SimpleGrantedAuthority> rolelist) {
		this.rolelist = rolelist;
	}
	
	
}
