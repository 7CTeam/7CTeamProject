package com.istrom.dao.db;

import java.util.List;

import org.apache.ibatis.annotations.Param;

import com.istrom.po.DbUser;
import com.istrom.po.Role;

public interface UserDb {
	
	public List<DbUser> get();
	
	public List<Role> getRoleList(@Param("user_id") String user_id);
}
