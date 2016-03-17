# FlaskLoginManagement
learning flask

## 需求
实现一个账号系统，需要实现多种登录方式的绑定与解绑，以及多点登录的管理。具体需求如下：

- [x] 用户可以通过邮箱、微博和 QQ 空间三种方式登录；
- [x] 通过其中一种方式登录后，可以设置其他登录方式；
- [ ] 拥有两种以上登录方式时，可以解绑其中任意一种，但最后一种登录方式不能解绑；
- [ ] 一个解绑后的登录方式可以用于登录新的账号；
- [x] 用户可从多处登录，在一处登录后可查看该用户当前所有在线登录，并可注销其中任意一个。被注销的登录需要重新登录，未被注销的登录不受影响。

需求 5 举例，用户在 Chrome 和 Firefox 分别登录，标记为登录 1 和登录 2，用户可以看到当前有 2 个在线登录。用户注销登录 2 后，Firefox 需要重新登录，但 Chrome 不受影响。


## 效果

目前已经完成的部分

### 首页：
![首页](http://ww3.sinaimg.cn/large/bfe31badjw1f1wdau27g3j20hs0vkt9q.jpg)

### 注册页面：
![注册](http://ww1.sinaimg.cn/large/bfe31badjw1f1wdbao1jyj20hs0vkaba.jpg)

### 发送验证邮件：
![发送验证邮件](http://ww4.sinaimg.cn/large/bfe31badjw1f1wdbw6nuzj20hs0vk75g.jpg)

### tokenzied的验证邮件：
![tokenzied的验证邮件](http://ww3.sinaimg.cn/large/bfe31badjw1f1wdcg5fcaj20hs0vkdht.jpg)

### 微博登录：
![微博登录](http://ww2.sinaimg.cn/large/bfe31badgw1f208e8jzuej20l80clwfx.jpg)

### 登录界面：
![登录](http://ww4.sinaimg.cn/large/bfe31badjw1f1wd8753pej20hs0vkgmr.jpg)

### 已登录客户端:
![已登录客户端](http://ww3.sinaimg.cn/large/bfe31badjw1f1wd9pk8cwj20hs0vkac9.jpg)

### 登录后绑定新的登录方式：
![登录后绑定新的登录方式](http://ww3.sinaimg.cn/large/bfe31badgw1f208emsf3vj20ul0ao0uf.jpg)
