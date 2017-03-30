package com.istrom.dao.db;

import java.util.List;

import org.apache.ibatis.annotations.Param;

public interface RoleDb {
	
	public List<String> get();
	
	public List<String> getRoleName(@Param("user_id") String user_id);
	
}
