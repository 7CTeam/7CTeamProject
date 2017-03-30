package com.istrom.dao.db;

import java.util.List;

import org.apache.ibatis.annotations.Param;

public interface ResourceDb {
	
	public List<String> getResUrl(@Param("name") String name);
	
}
