package org.springframework.security.core.userdetails.util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Hashtable;

public class HideMenuUtil {
	public static Hashtable<String,String> getAllSidCid(){
		Hashtable<String,String> sidCidTable;
        Connection conn;
        PreparedStatement pstmt;
        ResultSet rs;
        sidCidTable = null;
        conn = null;
        pstmt = null;
        rs = null;
        try{
            conn =  ConnectionFactoryMain.getConnection();
            String strSql = "select sid,cid,open_day from cfg_hide_sid_cid ; ";
            pstmt = conn.prepareStatement(strSql);
            rs = pstmt.executeQuery();
            sidCidTable = new Hashtable<String,String>();
            String sid;
            String cid;
            String open_day;
            for(; rs.next(); sidCidTable.put(sid, cid+"#"+open_day)){
                sid = rs.getString("sid");
                cid = rs.getString("cid")==null?"":rs.getString("cid");
                open_day = rs.getString("open_day")==null?"":rs.getString("open_day");
            }
        }catch(Exception e){
			e.printStackTrace();
		}finally{
			try {rs.close();} catch (SQLException e) {e.printStackTrace();}
			try {conn.close();} catch (SQLException e) {e.printStackTrace();}
		}
		return sidCidTable;
    }    
}
