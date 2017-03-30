package com.istrom.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.jasig.cas.client.authentication.AttributePrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.istrom.dao.db.ResourceDb;
import com.istrom.dao.db.RoleDb;
import com.istrom.dao.db.UserDb;
import com.istrom.po.DbUser;
import com.istrom.po.Role;

@Service
public class CasUserDetailService implements AuthenticationUserDetailsService{
	
	protected static Logger logger = Logger.getLogger("CasUserDetailService");  
	
	@Autowired
	private UserDb userDb;
	
	@Override
	public UserDetails loadUserDetails(Authentication authentication) throws UsernameNotFoundException {
		CasAssertionAuthenticationToken casAssertionAuthenticationToken = (CasAssertionAuthenticationToken) authentication;
        AttributePrincipal principal = casAssertionAuthenticationToken.getAssertion().getPrincipal();
        Map attributes = principal.getAttributes();
        String userid = (String) attributes.get("userid");
        String uname = (String) attributes.get("username");
        String email = (String) attributes.get("email");
        String username = authentication.getName();
        
        CasMetadataSource.setDbUser(getDatabase(username));
        
        Collection<SimpleGrantedAuthority> collection =  getRoleList(getDatabase(username).getId());  
        
        return new User(username, "", collection);
	}
	
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
	

}
