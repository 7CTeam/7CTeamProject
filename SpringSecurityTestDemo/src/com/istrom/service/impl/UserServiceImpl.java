package com.istrom.service.impl;

import java.util.List;

import javax.annotation.Resource;

import org.springframework.stereotype.Service;

import com.istrom.dao.UserDao;
import com.istrom.po.DbUser;
import com.istrom.service.UserService;

@Service
public class UserServiceImpl implements UserService {
	
	@Resource
	private UserDao userDao;

	@Override
	public void printfUser() {
		System.out.println(userDao.getDatabase("admin"));
	}

	@Override
	public List<DbUser> loadUserInfo() {
		
		return userDao.loadUserInfo();
	}

}
