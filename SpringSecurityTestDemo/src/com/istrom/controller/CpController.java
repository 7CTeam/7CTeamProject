package com.istrom.controller;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/cp")
public class CpController {
	
	protected static Logger logger = Logger.getLogger("controller");  
	  
    /** 
     * Ìø×ªµ½cpÒ³Ãæ 
     *  
     * @return 
     */  
    @RequestMapping(value = "/cp")  
    public String getCommonPage() {  
        logger.debug("Received request to show cp page");  
        return "cp/userInfo";  
    }  
    
}
