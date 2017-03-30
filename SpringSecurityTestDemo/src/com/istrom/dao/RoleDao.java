package com.istrom.dao;

import java.util.List;

import javax.annotation.Resource;

import com.istrom.dao.db.RoleDb;

public class RoleDao {
	
	@Resource
	private RoleDb roleDb;
	
	public List<String> getRoleName(){
		return null;
	}
}
