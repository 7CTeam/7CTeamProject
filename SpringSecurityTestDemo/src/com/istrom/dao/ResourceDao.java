package com.istrom.dao;

import java.util.List;

import javax.annotation.Resource;

import com.istrom.dao.db.ResourceDb;

public class ResourceDao {
	
	@Resource
	private ResourceDb resourceDb;
	
	public List<String> getResUrl(String roleName){
		return resourceDb.getResUrl(roleName);
	}
}
