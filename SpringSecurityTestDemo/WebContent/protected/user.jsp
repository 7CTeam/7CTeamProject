<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>用户操作</title>
<link href="${pageContext.request.contextPath}/resources/wel_data/right.css" rel="stylesheet" type="text/css">
<link href="${pageContext.request.contextPath}/resources/wel_data/gray.css" rel="stylesheet" type="text/css">
<script type="text/javascript" src="${pageContext.request.contextPath}/resources/sysjs/jquery-1.7.js"></script>
<script type="text/javascript">
	function delUser(id)
	{
		if(confirm('真的要删除吗？'))
		{
			window.location.href = "action.jsp?type=6&id=" + id;	
		}
	}
	
	$(function()
	{
		$.ajax({
			url : "${pageContext.request.contextPath}/user/loadUser",
			type : "post",
			dataType : "json",
			success : function(result) {
				if (result.status == 0) {
					var html='';
					var msg = result.data;
					$("#userInfo").val("");
					for(i in msg){
						html += "<tr>"
								 +"<td>"+msg[i].id+"</td>"
								 +"<td>"+msg[i].username+"</td>"
								 +"<td>"+msg[i].realname+"</td>"
								 +"<td>"
								 	+"<a href='${pageContext.request.contextPath}/user/edit'>修改</a>"
								 	+"<a href=''>角色分配</a>"
								 +"</td>"
							 	+"</tr>";
					}
					$("#userInfo").append(html);
				} 
			},
			error : function() {
				alert("error!");
			}
		});
	});
	
	
</script>

<body>
	<div class="main_content">
		<div class="content" >
			<dl>
				<dd class="ddbtn" ><a href="useradd.jsp">增  加</a></dd>
			</dl>
			<form action="user.jsp"  method="post" style="margin-top: 10px">
				<dl>
					<dd class="dd01_me">角色</dd>
					<dd class="dd04_me">
						<select name="group_id" id="sel_group_id" >
							<option value="-1">全部</option>
							
						</select>
					</dd>
					<dd class="dd01_me">登录名</dd>
					<dd class="dd03_me">
						<input name="username" id="input_username" value="" type="text" style="width: 150px">
					</dd>
					<dd class="dd01_me">昵称</dd>
					<dd class="dd03_me">
						<input name="nickname" id="input_nickname" value="" type="text" style="width: 150px">
					</dd>
					<dd class="ddbtn" style="margin-left: 10px; margin-top: 0px;">
						<input class="btn_match" name="search" value="查     询" type="submit" />
					</dd>
				</dl>
			</form>
		</div>
		<table cellpadding="0" cellspacing="0">
			<thead>
				<tr>
					<td>ID</td>
					<td>登录名</td>
					<td>昵称</td>
					<td>操作</td>
				</tr>
			</thead>
			<tbody id="userInfo">
				
			</tbody>
		</table>
	</div>
	
</body>
</html>