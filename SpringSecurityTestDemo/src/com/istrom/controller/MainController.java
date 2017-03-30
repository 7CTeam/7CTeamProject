package com.istrom.controller;

import javax.annotation.Resource;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import com.istrom.service.UserService;

@Controller
@RequestMapping("/main")
public class MainController {
	
	@Resource
	private UserService userService;
	
	protected static Logger logger = Logger.getLogger("controller");  
	  
    /** 
     * 跳转到commonpage页面 
     *  
     * @return 
     */  
    @RequestMapping(value = "/common")  
    public String getCommonPage() {  
        logger.debug("Received request to show common page");  
        userService.printfUser();
        return "userInfo";  
    }  
  
    /** 
     * 跳转到adminpage页面 
     *  
     * @return 
     */  
    @RequestMapping(value = "/admin")  
    public String getAadminPage() {  
        logger.debug("Received request to show admin page");  
        return "protected/index";  
  
    }  
}
