package org.springframework.security.core.userdetails;

import org.jasig.cas.client.authentication.AttributePrincipal;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.istrom.dao.UserDao;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/**
 * Created by fengjing on 2016/4/30.
 */
public class CasUserDetailService implements AuthenticationUserDetailsService {

    @Override
    public UserDetails loadUserDetails(Authentication authentication) throws UsernameNotFoundException {
        CasAssertionAuthenticationToken casAssertionAuthenticationToken = (CasAssertionAuthenticationToken) authentication;
        AttributePrincipal principal = casAssertionAuthenticationToken.getAssertion().getPrincipal();
        Map attributes = principal.getAttributes();
        String userid = (String) attributes.get("userid");
        String uname = (String) attributes.get("username");
        String email = (String) attributes.get("email");
        String username = authentication.getName();
        
        Collection<SimpleGrantedAuthority> collection = new UserDao().getDatabase(username).getRolelist();
        return new User(username, "", collection);
        
    }
}
