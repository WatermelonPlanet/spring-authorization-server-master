## 😄Spring Authorization Server (2) 【授权服务、资源服务、客户端服务】初步认识

### demo-authorizationserver[授权服务]

**授权模式**

- **授权码模式**

  - **获取授权码[authorization_code]**
    ![img_1.png](image/img_1.png)
  - **用浏览器打开:**
    http://127.0.0.1:9000/oauth2/authorize?client_id=messaging-client&response_type=code&scope=message.read&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc
    会重定向到登录页面
    ![img_2_1.png](image/img_2_1.png)
  - **看看授权服务器输出的日志**，有兴趣想走走源码流程的看看就行

    ````java
    //DelegatingAuthenticationEntryPoint
    //LoginUrlAuthenticationEntryPoint
    s.w.a.DelegatingAuthenticationEntryPoint : Match found! Executing org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint@42c3e7fd
    ````

    ![img_3.png](image/img_3.png)
  - **登录**

    ````java
    // 内存里初始化了一个用户，直接使用这个用户名和密码进行登录
    @Bean
    public UserDetailsService users() {
        UserDetails user = User.withDefaultPasswordEncoder()
                    .username("user1")
                    .password("password")
                    .roles("USER")
                    .build();
        return new InMemoryUserDetailsManager(user);
    }
    ````

    ![img_2_1.png](image/img_2_1.png)
  - **登录成功后会进入授权页（oauth2/consent），进行确认授权**

    ````java
     //AuthorizationServerConfig 授权页配置
     //授权页路径配置（可以相对路径或绝对路径）
     private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";

     http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
             .deviceVerificationEndpoint(deviceVerificationEndpoint ->
                     deviceVerificationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI)
             )
             .authorizationEndpoint(authorizationEndpoint ->
                     authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI))
             ...;   

     //requireAuthorizationConsent(true):[true 有授权页，false：无授权页] 备注：授权过一次就不会出现了，因为会持久化到数据库，目前demo基于H2重启后数据就没有了 
     RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("messaging-client")
                    .clientSecret("{noop}secret")
                    ...
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                    .build();
    ````

    ![img_4.png](image/img_4.png)
  - **获取授权码-从url上获取“code=”后面的值**
    http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc?code=gMXmx2YHmwNFXMjXjgWaveNxspAEUy3q5Jc3m8h-NSjWzYbLAEmraDaUZkFhyBVTrRQlyDMWhePfEUe4Wb2g7sj1Q-mBq9HBTyCwL1qMvRNFEx-UTUtlVNFP7rZnfVWR

    ![image.png](image/img_5.png)
  - **获取token**

    **参数说明**


    | 参数名       | 示例值             | 描述                                  |
    | -------------- | -------------------- | --------------------------------------- |
    | grant_type   | authorization_code | 授权类型，固定为 "authorization_code" |
    | code         | your_code_here     | 授权服务器返回的授权码                |
    | redirect_uri | your_redirect_uri  | 客户端事先注册的回调 URL              |
    | client_id    | your_client_id     | 客户端的标识                          |

    ![img_5_1.png](image/img_5_1.png)
    ![img_5_2.png](image/img_5_2.png)
    ![img_5_3.png](image/img_5_3.png)


    ````json
    {
     "access_token": "eyJraWQiOiI4ZWIxYmYyYS04ZGM0LTRkNGItYjU5OS02NTYxNjhhMWQzODEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSIsImF1ZCI6Im1lc3NhZ2luZy1jbGllbnQiLCJuYmYiOjE2OTMyNzkxODksInNjb3BlIjpbIm1lc3NhZ2UucmVhZCJdLCJpc3MiOiJodHRwOi8vMTI3LjAuMC4xOjkwMDAiLCJleHAiOjE2OTMyNzk0ODksImlhdCI6MTY5MzI3OTE4OX0.fN-GTW15smqjopGO5FgWhfor5JfjNMYRVCne6TeuIdkW1uQPA1Rv9AJ-T_G2o2d8r7p3hK0pKPF9A0nl1OdXzJmtsDiCapmqqvo-UW01z4Q7FBlnzXClZYNhbf4KjkrUk3v4liAfzlCiOs2IdMW7Z26-lvXZpsNUTys5WBy99NAuOM9WlCbb8_AWpK39bBapybUTcNxzjd-rBdmpy4brJJH8IVWiKY4Mf_HoPRERexzemil_nviHt-lf2pBhafiJEiyf24VueYDEXdHjqyJZqE_-2Rzj8_sJeE6b_WaHxmKuj3ioYr2ZLqSvhM5fiAOn3oUqEj0G1tQT8oWTF5PwuA",
     "refresh_token": "-hn6N3M6UizLpp8MhyDcjF9qsqUixnzpZtqg_ToPcJWdVbQC4Y5n_wXQZXuchFWKHBLnD1GOBEhdusPxIAizOi7rYz1y-s8ex3bxSI0irgr8zf8QeNXvT6kz8u6ZFE8_",
     "scope": "message.read",
     "token_type": "Bearer",
     "expires_in": 299
     }
    ````
  - **[jwt解析](https://www.box3.cn/tools/jwt.html)**
    ![img_5_4.png](image/img_5_4.png)
- **刷新token**

  - **参数说明**


    | 参数名        | 示例值                                                                                                                           | 描述                                |
    | --------------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
    | grant_type    | refresh_token                                                                                                                    | 刷新token，固定为 "refresh_token"   |
    | refresh_token | -hn6N3M6UizLpp8MhyDcjF9qsqUixnzpZtqg_ToPcJWdVbQC4Y5n_wXQZXuchFWKHBLnD1GOBEhdusPxIAizOi7rYz1y-s8ex3bxSI0irgr8zf8QeNXvT6kz8u6ZFE8_ | /oauth2/token返回的refresh_token 值 |
  - **请求示例**

    http://127.0.0.1:9000/oauth2/token?grant_type=refresh_token&refresh_token=-hn6N3M6UizLpp8MhyDcjF9qsqUixnzpZtqg_ToPcJWdVbQC4Y5n_wXQZXuchFWKHBLnD1GOBEhdusPxIAizOi7rYz1y-s8ex3bxSI0irgr8zf8QeNXvT6kz8u6ZFE8_

    ![img_6.png](image/img_6.png)
    ![img_6_1.png](image/img_6_1.png)
    ![img_6_2.png](image/img_6_2.png)
- **设备码模式**

  - **参数说明**


    | 参数名     | 示例值                  | 描述                                         |
    | ------------ | ------------------------- | ---------------------------------------------- |
    | grant_type | device-messaging-client | 设备码类型，固定为 "device-messaging-client" |
    | scope      | message.read            | 作用域                                       |
  - **请求示例**

    http://127.0.0.1:9000/oauth2/device_authorization
    ![img_7.png](image/img_7.png)

    ````json
      {
       "user_code": "VRFP-TJHW",
       "device_code": "4ZE1FZtPKBki3GVC-YBsnqhxjzQVwSTcBPchE_WKOQL4dg5qw9Z4-4NdTqLPPKknTOKPAy85_ASiKC6Ki-cBNDRLMIil9cK6Dj3HScx1CHvI3qlXDuCzsUk_0sQh-z6b",
       "verification_uri_complete": "http://127.0.0.1:9000/activate?user_code=VRFP-TJHW",
       "verification_uri": "http://127.0.0.1:9000/activate",
       "expires_in": 300
      }
    ````
  - **verification_uri：http://127.0.0.1:9000/activat**
    ![img_7_1.png](image/img_7_1.png)
  - **填入 user_code**
    ![img_7_2.png](image/img_7_2.png)
  - **验证 user_code**
    ![img_7_3.png](image/img_7_3.png)
  - **verification_uri_complete** 这个url是携带了验证码（?user_code=VRFP-TJHW）

### messages-resource[资源服务]

**资源服务的yml配置**

- **授权服务器配置**

  ````yaml
  spring:
    security:
      oauth2:
        resourceserver:
           jwt:
             issuer-uri: http://127.0.0.1:9000 # 授权服务器（访问资源服务器时会到授权服务器中验证token）
  ````
- **从授权服务器获取到token后，携带token访问资源服务器示例**

  ![img_8.png](image/img_8.png)
- **用jwt工具看看“access_token”的值解析出来有什么**

  ````json
  {
  "sub": "user1",//用户名
  "aud": "messaging-client",//客户端id
  "nbf": 1693291796,
  "scope": ["message.read"],
  "iss": "http://127.0.0.1:9000",//授权服务器
  "exp": 1693292096,
  "iat": 1693291796
  }
  ````

  ![img_8_1.png](image/img_8_1.png)
- **有一种情况，携带有效切正确的“access_token”会导致访问资源服务401，并非跨域问题导致**

  - **资源服务器yml配置如下**

    ````yaml
    spring:
      security:
        oauth2:
          resourceserver:
             jwt:
               issuer-uri: http://localhost:9000
    ````

    ![img_8_4.png](image/img_8_4.png)
    ![img_8_3.png](image/img_8_3.png)
    **spring.security.oauth2.resourceserver.jwt.issuer-uri配置值与“access_token”中"iss"值不一致**，则会抛出 【 The iss claim is not valid】异常，最终导致401的问题。
  - **如何解决这个问题呢？**

    **<span style="color:green;">在授权服务器获取 “access_token” 时 请求使用的是哪一个域，spring.security.oauth2.resourceserver.jwt.issuer-uri配置值也使用同一个域</span>**

### demo-client[客户端服务]

**客户端服务yml配置**

- **客户端配置**  [`官方说明`](https://docs.spring.io/spring-security/reference/6.1-SNAPSHOT/servlet/oauth2/login/core.html)
  ````yaml
  spring:
    security:
      oauth2:
        client:
          registration:
             messaging-client-oidc: # 这个是我们自己定义客户端
                provider: spring 
                client-id: messaging-client #客户端id
                client-secret: secret # 客户端id
                authorization-grant-type: authorization_code # 授权码模式
                redirect-uri: "http://127.0.0.1:8080/login/oauth2/code/{registrationId}" # 这个是一个模板 {baseUrl}/login/oauth2/code/{registrationId} 官方说明：https://docs.spring.io/spring-security/reference/6.1-SNAPSHOT/servlet/oauth2/login/core.html
                scope: openid, profile
                client-name: messaging-client-oidc
          provider:
            spring:
              issuer-uri: http://localhost:9000 # 这个对应的是我们自己的授权服务器
  ````

### 运行demo

**服务启动顺序**

- **①demo-authorizationserver[授权服务]**
- **②messages-resource[资源服务]**
- **③demo-client[客户端]**

**messages-resource[资源服务]和③demo-client[客户端]没有先后顺序，demo-client[客户端]依赖demo-authorizationserver[授权服务]的端点，否则启动抛异常。**

#### 举例理解【授权服务、资源服务、客户端服务】在微服务架构中担任什么样的一个角色和职责

假如我们有这样的一个微服务：【网关服务】、【认证服务】、【业务服务】

我们访问【业务服务】是通过【网关服务】进行转发的，【网关服务】判断是否登录或者有权限，如果没有登录或者没有权限，就会重定向到【认证服务】的进行登录，登录成功后，【认证服务】把token返回给【网关服务】，【网关服务】会携带token去访问【业务服务】，这样就完成了整个认证和鉴权过程，然后token是存储在【网关服务】的，也没有暴露出来，是不是比较安全

![img_10.png](image/img_10.png)

demo-client可以把它看作我们的【网关服务】，demo-authorizationserver可以看作我们的【认证服务】，messages-resource可以看作【业务服务】，你这样去理解是否能够理解oauth2的这个流程了呢。


<iframe src="html/video_1.html" frameborder="0" allowfullscreen></iframe>

[![demo视频]](html/video_1.html)


**希望以上流程能够帮助到理解😄**
