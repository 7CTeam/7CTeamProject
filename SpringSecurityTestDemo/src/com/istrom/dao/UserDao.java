package com.istrom.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.annotation.Resource;

import org.apache.log4j.Logger;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.util.ConnectionFactory;
import org.springframework.stereotype.Repository;

import com.istrom.dao.db.UserDb;
import com.istrom.po.DbUser;
import com.istrom.po.Role;

@Repository
public class UserDao {
	
	@Resource
	private UserDb userDb;
	
	protected static Logger logger = Logger.getLogger("dao");  
	  
    public DbUser getDatabase(String username) {  
    	
  
        List<DbUser> users = userDb.get();
  
        for (DbUser dbUser : users) {  
            if (dbUser.getUsername().equals(username) == true) {  
                logger.debug("User found");  
                return dbUser;  
            }  
        }  
        
        logger.error("User does not exist!");  
        throw new RuntimeException("User does not exist!");  
  
    }  
  
    
    public Collection<SimpleGrantedAuthority> getRoleList(String userId){
    	Collection<SimpleGrantedAuthority> collection = new ArrayList<>();
    	
    	List<Role> list = userDb.getRoleList(userId);
    	for (Role role : list) {
			collection.add(new SimpleGrantedAuthority(role.getName()));
		}
    	
    	return collection;
    }
    
    public List<DbUser> loadUserInfo(){
    	return userDb.get();
    }
    
}
