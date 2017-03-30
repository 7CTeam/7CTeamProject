package com.istrom.controller;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/channel")
public class ChannelController {
	
	protected static Logger logger = Logger.getLogger("controller");  
	  
    /** 
     * Ìø×ªµ½channelÒ³Ãæ 
     *  
     * @return 
     */  
    @RequestMapping(value = "/channel")  
    public String getCommonPage() {  
        logger.debug("Received request to show channel page");  
        return "channel/userInfo";  
    }  
}
