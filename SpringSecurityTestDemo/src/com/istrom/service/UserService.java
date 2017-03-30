package com.istrom.service;

import java.util.List;

import com.istrom.po.DbUser;

public interface UserService {
	public void printfUser();
	
	public List<DbUser> loadUserInfo();
	
}
