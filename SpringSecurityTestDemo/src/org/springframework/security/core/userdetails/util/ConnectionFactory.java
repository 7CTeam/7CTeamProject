package org.springframework.security.core.userdetails.util;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.sql.DataSource;

import org.apache.tomcat.dbcp.dbcp.BasicDataSource;


public abstract class ConnectionFactory {
	static DataSource instance = null;
	public ConnectionFactory() {
	}

	public static synchronized Connection getConnection() throws SQLException {
		if(instance==null){
			instance=setupDataSource();
		}
		return instance.getConnection();
	}

	public static DataSource getDataSource() throws SQLException {
		return instance;
	}

	public static DataSource setupDataSource() {
		BasicDataSource ds = new BasicDataSource();
		ds.setDriverClassName("com.mysql.jdbc.Driver");	
		//System.out.println("security_master==="+ConfigManager.getConfigData("security_master.url"));
		ds.setUrl(ConfigManager.getConfigData("security_master.url"));
		ds.setUsername(ConfigManager.getConfigData("security_master.user"));
		ds.setPassword(ConfigManager.getConfigData("security_master.password"));
		/*
		ds.setUrl("jdbc:mysql://dbcasmaster.istorm.cn:1433/mcoo");
		ds.setUsername("root");
		ds.setPassword("mcoo789456");
		*/
		ds.setInitialSize(2);
		ds.setMaxActive(5);		
		ds.setMaxIdle(3);
		ds.setMinIdle(2);
		ds.setMaxWait(2048);
		return ds;
	}

	public static void printDataSourceStats(DataSource ds) throws SQLException {
		BasicDataSource bds = (BasicDataSource) ds;
		System.out.println("NumActive: " + bds.getNumActive());
		System.out.println("NumIdle: " + bds.getNumIdle());
	}

	public static void shutdownDataSource(DataSource ds) throws SQLException {
		BasicDataSource bds = (BasicDataSource) ds;
		bds.close();
	}
	
	public static void main(String args[]) {
		try {
			Connection conn;
			Statement stmt;
			ResultSet rset;
			System.out.println("Setting up data source.");
			System.out.println("Done.");
			conn = null;
			stmt = null;
			rset = null;
			System.out.println("Creating connection.");
			conn = getConnection();
			printDataSourceStats(getDataSource());
			System.out.println("Creating statement.");
			stmt = conn.createStatement();
			System.out.println("Executing statement.");
			rset = stmt.executeQuery("select * from user");
			System.out.println("Results:");
			int numcols = rset.getMetaData().getColumnCount();
			for (; rset.next(); ) {
				for (int i = 1; i <= numcols; i++){
						System.out.print("\t" + rset.getString(i));
				}
			    break;
			}
			try {
				rset.close();
			}
			catch (Exception e1) {
			}
			try {
				stmt.close();
			}
			catch (Exception e2) {
			}
			try {
				conn.close();
			}
			catch (Exception e3) {
			}
			try {
				printDataSourceStats(getDataSource());
			} catch (SQLException ex) {
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
