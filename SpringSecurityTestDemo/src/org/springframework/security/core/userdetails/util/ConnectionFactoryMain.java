package org.springframework.security.core.userdetails.util;

/*
 * Copyright 1999-2004 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import javax.sql.DataSource;

import org.apache.tomcat.dbcp.dbcp.BasicDataSource;

import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;
import java.sql.SQLException;

//
// Here are the dbcp-specific classes.
// Note that they are only used in the setupDataSource
// method. In normal use, your classes interact
// only with the standard JDBC API
//

import java.util.Hashtable;

//
// Here's a simple example of how to use the BasicDataSource.
// In this example, we'll construct the BasicDataSource manually,
// but you could also configure it using an external conifguration file.
//

//
// Note that this example is very similiar to the PoolingDriver
// example.

//
// To compile this example, you'll want:
//  * commons-pool.jar
//  * commons-dbcp.jar
//  * j2ee.jar (for the javax.sql classes)
// in your classpath.
//
// To run this example, you'll want:
//  * commons-collections.jar
//  * commons-pool.jar
//  * commons-dbcp.jar
//  * j2ee.jar (for the javax.sql classes)
//  * the classes for your (underlying) JDBC driver
// in your classpath.
//
// Invoke the class using two arguments:
//  * the connect string for your underlying JDBC driver
//  * the query you'd like to execute
// You'll also want to ensure your underlying JDBC driver
// is registered.  You can use the "jdbc.drivers"
// property to do this.
//
// For example:
//  java -Djdbc.drivers=oracle.jdbc.driver.OracleDriver \
//       -classpath commons-collections.jar:commons-pool.jar:commons-dbcp.jar:j2ee.jar:oracle-jdbc.jar:. \
//       ManualPoolingDataSourceExample
//       "jdbc:oracle:thin:scott/tiger@myhost:1521:mysid"
//       "SELECT * FROM DUAL"
//
public abstract class ConnectionFactoryMain {
    //static ConnectionFactory instance = null;
    static DataSource instance = setupDataSource();

    public synchronized static Connection getConnection() throws SQLException {
        return instance.getConnection();
//        Connection conn =null;
//
//        try	{
//                Class.forName("com.mysql.jdbc.Driver");
//                conn = DriverManager.getConnection("jdbc:mysql://218.16.120.252:3306/downfun","root","vaflsroot!#123*()");
//        } catch(Exception e) {
//                System.out.println(e.toString());
//        }
//        return conn;

    }

    public static DataSource getDataSource() throws SQLException {
        return instance;
    }

    public static void main(String[] args) {
        // First we set up the BasicDataSource.
        // Normally this would be handled auto-magically by
        // an external configuration, but in this example we'll
        // do it manually.
//        //
//        System.out.println("Setting up data source.");
//        System.out.println("Done.");
//        Connection conn = null;
//        Statement stmt = null;
//        Statement stmt2 = null;
//        Statement stmt3 = null;
//        ResultSet rs = null;
//        ResultSet rs2 = null;
//
//        try {
//            System.out.println("Creating connection.");
//            conn = ConnectionFactorySlave.getConnection();
//            printDataSourceStats(ConnectionFactorySlave.getDataSource());
//            System.out.println("Creating statement.");
//            stmt = conn.createStatement();
//            stmt2 = conn.createStatement();
//            stmt3 = conn.createStatement();
//            System.out.println("Executing statement.");
//            rs = stmt.executeQuery("select * from smsmo200809 where price=0");
//            Hashtable linkidTable = new Hashtable();
//            int count = 0;
//            while(rs.next()) {
//                String linkId = rs.getString("linkID");
//                System.out.println((count++)+":"+linkId);
//                rs2 = stmt2.executeQuery("select * from smsmo200808 where linkid = '"+linkId+"'");
//                if (rs2.next()){
//                    stmt3.executeUpdate("update smsmo200809 se sid=5000,cid=1000,mid='"+rs2.getString("mid")+"',feeMobile='"+rs2.getString("feeMobile")+"',serviceCode='"+rs2.getString("serviceCode")+"',spNum='"+rs2.getString("spNum")+"',serviceName='"+rs2.getString("serviceName")+"',moMsg='"+rs2.getString("moMsg")+"',price="+rs2.getString("price")+",area='"+rs2.getString("area")+"',produce='"+rs2.getString("produce")+"' where linkid='"+linkId+"'");
//                }
//            }
//        } catch(SQLException e) {
//            e.printStackTrace();
//        } finally {
//            try { rs.close(); } catch(Exception e) { }
//            try { stmt.close(); } catch(Exception e) { }
//            try { conn.close(); } catch(Exception e) { }
//            try {
//                ConnectionFactorySlave.printDataSourceStats(ConnectionFactorySlave.
//                        getDataSource());
//            } catch (SQLException ex) {
//            }
//        }
        //
        // Now, we can use JDBC DataSource as we normally would.
        //

    }

    public static DataSource setupDataSource() {
        BasicDataSource ds = new BasicDataSource();
//        ds.setDriverClassName("oracle.jdbc.driver.OracleDriver");
//        ds.setUrl("jdbc:oracle:thin:@219.133.55.18:1521:powerora");
////        ds.setUrl("jdbc:oracle:thin:@192.168.0.1:1521:poweredu");
//        ds.setUsername("20home");
//        ds.setPassword("20home!#123");
//        ds.setUsername("bm");
//        ds.setPassword("poweroracle");
        
        //ConfigManager cm = new ConfigManager();
        
        ds.setDriverClassName("com.mysql.jdbc.Driver");
        ds.setUrl(ConfigManager.getConfigData("security_master.url"));
        ds.setUsername(ConfigManager.getConfigData("security_master.user"));
        ds.setPassword(ConfigManager.getConfigData("security_master.password"));
//        ds.setUrl("jdbc:mysql://localhost:3306/mcoo");
//        ds.setUsername("root");
//        ds.setPassword("123456");
        ds.setInitialSize(20);
        ds.setMaxActive(200);
        ds.setMaxIdle(16);
        ds.setMinIdle(8);
        ds.setMaxWait(2000);

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
}
