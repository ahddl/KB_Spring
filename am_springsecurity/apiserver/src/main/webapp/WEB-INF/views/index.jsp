<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib uri="http://www.springframework.org/security/tags" prefix="sec" %>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
<h1>메인페이지 입니다.</h1>
<body bgcolor="#adff2f"><sec:authorize access="isAnonymous()">
    <a href="/security/login"> </a>
</sec:authorize>

<sec:authorize access="isAuthenticated()">
    <sec:authentication property="principal.username"/>
    <form action="/security/logout" method="post">
        <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
        <input type="submit" value=" "/>
    </form>
</sec:authorize>
</body>
</html>