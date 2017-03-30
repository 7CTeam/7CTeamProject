<%@page import="org.springframework.security.cas.authentication.CasAuthenticationToken" %>
<%@page import="org.jasig.cas.client.validation.AssertionImpl" %>
<%@page import="org.springframework.security.core.context.SecurityContextHolder" %>
<%@ page pageEncoding="UTF-8" %>
<%@ page contentType="text/html; charset=UTF-8" %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<!DOCTYPE html>
<html>
<head>
    <title>Spring Security CAS CHANNEL Client</title>
    <meta charset="UTF-8"/>
    <link rel="stylesheet" href="${pageContext.request.contextPath}/resources/css/bootstrap.min.css"/>
</head>
<body>
<div class="container">
    <ul class="nav nav-tabs">
        <li class="active"><a href="main/common">You are on the /index.jsp page</a></li>
        <li><a href="main/admin">Call the /protected/index.jsp page</a></li>
        <!-- #### change with your own CAS server and your host name #### -->
        <li><a href="http://localhost:8080/cas/logout?service=http://localhost:8081">Call the CAS logout</a></li>
    </ul>
    <br>
    <h3>
        <p>CHANNEL</p>
    </h3>
</div>
</body>
</html>