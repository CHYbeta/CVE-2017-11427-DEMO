# CVE-2017-11427-DEMO
基本环境
```
$ sudo apt-get install libxml2-dev libxslt1-dev
$ sudo apt-get install libxml2-dev libxmlsec1-dev libxmlsec1-openssl
```

DEMO:
```
$ git clone https://github.com/CHYbeta/CVE-2017-11427-DEMO.git
$ cd CVE-2017-11427-DEMO
$ source venv/bin/active
$ cd vuln_saml
$ python index.py
```

账号:
```
username: user_evil
password: iamuser1
email: demo@chybeta.com.evil

username: user_normal
password: iamuser2
email: demo@chybeta.com
```

# Analysis
[漏洞分析与实践之基于SAML实现的单点登录系统](https://xianzhi.aliyun.com/forum/topic/2093)

# Attack
首先登录用户 user_evil。用burp截取SAMLResponse字段值。
![](https://github.com/CHYbeta/chybeta.github.io/blob/master/images/pic/20180303/3.png?raw=true)

选择Action-> send to repeater，为后续做准备。

接着Forward，使用户 user_evil　认证成功。
![](https://github.com/CHYbeta/chybeta.github.io/blob/master/images/pic/20180303/4.png?raw=true)

将上述的SAMLResponse字段值先进行一次urldecode,然后去掉换行符，最后进行base64解码。将解码后的xml文件中的`emailAddress`和`Attribute`修改为`demo@chybeta.com<!-- -->.evil`，也即在原本认证用户的邮箱`demo@chybeta.com.evil`之间插入了注释。
![](https://github.com/CHYbeta/chybeta.github.io/blob/master/images/pic/20180303/5.png?raw=true)

接着将修改后的xml进行base64编码，接着urlencode，替换原本的SAMLResponse值，获得新的session
![](https://github.com/CHYbeta/chybeta.github.io/blob/master/images/pic/20180303/6.png?raw=true)

用这个新的session去登录:
![](https://github.com/CHYbeta/chybeta.github.io/blob/master/images/pic/20180303/7.png?raw=true)

user.email已经变为`demo@chybeta.com`，登录用户`user_normal`成功。

# 说明
+ 本环境仅为供大家测试与技术交流使用，请勿用于非法用途。
+ 注册oneLogin时并未验证邮箱的有效性，因此上述提供的账号并未涉及个人信息。同时也希望本DEMO的使用者不要试图更改密码，谢谢。