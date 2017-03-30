package org.springframework.security.core.userdetails.util;

import java.sql.*;
import javax.sql.DataSource;

import org.apache.tomcat.dbcp.dbcp.BasicDataSource;

public abstract class ConnectionFactoryMainOracle
{

    public ConnectionFactoryMainOracle()
    {
    }

    public static synchronized Connection getConnection()
        throws SQLException
    {
        return instance.getConnection();
    }

    public static DataSource getDataSource()
        throws SQLException
    {
        return instance;
    }

    public static DataSource setupDataSource()
    {
    	 BasicDataSource ds = new BasicDataSource();
    	    ds.setDriverClassName("oracle.jdbc.driver.OracleDriver");
    	    ds.setUrl("jdbc:oracle:thin:@192.168.10.122:8331:sz5gdw");
    	    ds.setUrl("jdbc:oracle:thin:@119.147.25.122:8331:sz5gdw");
    	    ds.setUsername("dw5g");
    	    ds.setPassword("cp5tpzd");
    	    ds.setInitialSize(4);
    	    ds.setMaxActive(32);
    	    ds.setMaxIdle(8);
    	    ds.setMinIdle(4);
    	    ds.setMaxWait(2048L);
    	    return ds;
    }

    public static void printDataSourceStats(DataSource ds)
        throws SQLException
    {
        BasicDataSource bds = (BasicDataSource)ds;
        System.out.println((new StringBuilder("NumActive: ")).append(bds.getNumActive()).toString());
        System.out.println((new StringBuilder("NumIdle: ")).append(bds.getNumIdle()).toString());
    }

    public static void shutdownDataSource(DataSource ds)
        throws SQLException
    {
        BasicDataSource bds = (BasicDataSource)ds;
        bds.close();
    }

    public static void main(String args[])
    {
    }

    static DataSource instance = setupDataSource();

}

