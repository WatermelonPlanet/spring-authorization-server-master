## 😄Spring Authorization Server (2) 【授权服务、资源服务、客户端服务】初步认识

#### demo-authorizationserver[授权服务]

1.👉 主要的配置类

* DefaultSecurityConfig

````java

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

    // 过滤器链
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize ->//① 配置鉴权的
                        authorize
                                .requestMatchers("/assets/**", "/webjars/**", "/login").permitAll() //② 忽略鉴权的url
                                .anyRequest().authenticated()//③ 排除忽略的其他url就需要鉴权了
                )
                .formLogin(formLogin ->
                        formLogin
                                .loginPage("/login")//④ 授权服务认证页面（可以配置相对和绝对地址，前后端分离的情况下填前端的url）
                )
                .oauth2Login(oauth2Login ->
                        oauth2Login
                                .loginPage("/login")//⑤ oauth2的认证页面（也可配置绝对地址）
                                .successHandler(authenticationSuccessHandler())//⑥ 登录成功后的处理
                );

        return http.build();
    }


    private AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new FederatedIdentityAuthenticationSuccessHandler();
    }

    // 初始化了一个用户在内存里面（这样就不会每次启动就再去生成密码了）
    @Bean
    public UserDetailsService users() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user1")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }
}

````

* AuthorizationServerConfig

````java

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {


    private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";//这个是授权页

    //这个就是oauth2 授权服务的一个配置核心了 
    // 官方网站的说明更具体 https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http, RegisteredClientRepository registeredClientRepository,
            AuthorizationServerSettings authorizationServerSettings) throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        DeviceClientAuthenticationConverter deviceClientAuthenticationConverter =
                new DeviceClientAuthenticationConverter(
                        authorizationServerSettings.getDeviceAuthorizationEndpoint());
        DeviceClientAuthenticationProvider deviceClientAuthenticationProvider =
                new DeviceClientAuthenticationProvider(registeredClientRepository);

        // @formatter:off
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .deviceAuthorizationEndpoint(deviceAuthorizationEndpoint ->
                        deviceAuthorizationEndpoint.verificationUri("/activate")
                )
                .deviceVerificationEndpoint(deviceVerificationEndpoint ->
                        deviceVerificationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI)
                )
                .clientAuthentication(clientAuthentication ->
                        clientAuthentication
                                .authenticationConverter(deviceClientAuthenticationConverter)
                                .authenticationProvider(deviceClientAuthenticationProvider)
                )
                .authorizationEndpoint(authorizationEndpoint ->
                        authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI))
                .oidc(Customizer.withDefaults());    // Enable OpenID Connect 1.0
        // @formatter:on

        // @formatter:off
        http
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .oauth2ResourceServer(oauth2ResourceServer ->
                        oauth2ResourceServer.jwt(Customizer.withDefaults()));
        // @formatter:on
        return http.build();
    }

    // 这个就是客户端的获取方式了，授权服务内部会调用做一些验证 例如 redirectUri 
    // 官方给出的demo就先在内存里面初始化 也可以才有数据库的形式 实现 RegisteredClientRepository即可
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("messaging-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .postLogoutRedirectUri("http://127.0.0.1:8080/logged-out")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        RegisteredClient deviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("device-messaging-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("message.read")
                .scope("message.write")
                .build();

        // Save registered client's in db as if in-memory
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        registeredClientRepository.save(registeredClient);
        registeredClientRepository.save(deviceClient);

        return registeredClientRepository;
    }
    // @formatter:on
}

````

大概过下以上2个配置的内容，有印象就可以了，没有懂也没有关系，主要是后面看几种模式的时候会用到这些配置中的一些参数

2.👉 授权模式

* 授权码模式

  * 获取授权码
    ![img_1.png](image/img_1.png)
  * 用浏览器打开

    http://127.0.0.1:9000/oauth2/authorize?client_id=messaging-client&response_type=code&scope=message.read&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc

    ![img_2.png](image/img_2.png)
  * 重定向到登录页面

    看看打印的日志 有兴趣想走走源码流程的 看看这段日志

    ````java
    //DelegatingAuthenticationEntryPoint
    //LoginUrlAuthenticationEntryPoint
    s.w.a.DelegatingAuthenticationEntryPoint : Match found! Executing org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint@42c3e7fd
    ````

    ![img_3.png](image/img_3.png)
  * 登录 [用户和密码在DefaultSecurityConfig中就初始化了]
    ![img_2_1.png](image/img_2_1.png)
  * 进入授权页[确认授权]
    ![img_4.png](image/img_4.png)

    oauth2/consent也就是 AuthorizationServerConfig中的配置 这个也可以自行更换
  * 获取到授权码-获取token

    http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc?code=gMXmx2YHmwNFXMjXjgWaveNxspAEUy3q5Jc3m8h-NSjWzYbLAEmraDaUZkFhyBVTrRQlyDMWhePfEUe4Wb2g7sj1Q-mBq9HBTyCwL1qMvRNFEx-UTUtlVNFP7rZnfVWR
    ![img_5.png](image/img_5.png)
    取code后面的值，也就是授权码
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
  * jwt解析：https://www.box3.cn/tools/jwt.html
    ![img_5_4.png](image/img_5_4.png)
* 刷新token

  * 取 **refresh_token**值

    http://127.0.0.1:9000/oauth2/token?grant_type=refresh_token&refresh_token=-hn6N3M6UizLpp8MhyDcjF9qsqUixnzpZtqg_ToPcJWdVbQC4Y5n_wXQZXuchFWKHBLnD1GOBEhdusPxIAizOi7rYz1y-s8ex3bxSI0irgr8zf8QeNXvT6kz8u6ZFE8_

    ![img_6.png](image/img_6.png)
    ![img_6_1.png](image/img_6_1.png)
    ![img_6_2.png](image/img_6_2.png)
* 设备码模式

  * 访问 http://127.0.0.1:9000/oauth2/device_authorization
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
  * 验证url：verification_uri：http://127.0.0.1:9000/activat
    ![img_7_1.png](image/img_7_1.png)
  * 验证码：user_code
    ![img_7_2.png](image/img_7_2.png)
  * 验证成功
    ![img_7_3.png](image/img_7_3.png)
  * 也可以直接使用 【verification_uri_complete】 这个url是直接携带了验证码的

#### messages-resource[资源服务]

1. yml中有这样一个配置

   ````yaml
   spring:
     security:
       oauth2:
         resourceserver:
            jwt:
              issuer-uri: http://127.0.0.1:9000 # 授权服务器（访问资源服务器时会到授权服务器中验证token）

   ````
2. 访问资源服务器

   ![img_8.png](image/img_8.png)

   ![img_8_1.png](image/img_8_1.png)
3. 有这样一种情况，会导致访问资源服务401，时间原因并非跨域问题

   配置如下：

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

   **spring.security.oauth2.resourceserver.jwt.issuer-uri** 配置值和访问授权服务器获取授权码时使用的是同一访问域不会出现该异常。
   例如：获取token就是使用的[http://127.0.0.1:9000/oauth2/token?grant_type=authorization_code&redirect_uri=http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc&code=96b9YX5fuJDa1yrbugnvf3EwwWAh-IF1WsepVcmuO3_JQ6ozhFaT6M_vwb69HiEgnBykTqU7_VN6nuDO9frk8j7jh1-ddqU-N7kaS7F_TLHyvoRD_ZBB7nMYv_jloks0]
   也就是[http://127.0.0.1:9000]，那**spring.security.oauth2.resourceserver.jwt.issuer-uri** 配置值也使用[http://127.0.0.1:9000]，因为jwt里中的["iss": "http://127.0.0.1:9000"] 会与 **spring.security.oauth2.resourceserver.jwt.issuer-uri**配置值做一个比较，两个值不一致会抛出 【o.s.s.oauth2.jwt.JwtClaimValidator  : The iss claim is not valid】异常，
   最终导致访问资源服务 401 (并非跨越问题)。

#### demo-client[客户端服务]

1.[yml配置客户端官方说明](https://docs.spring.io/spring-security/reference/6.1-SNAPSHOT/servlet/oauth2/login/core.html)
   ````yaml
   spring:
     security:
       oauth2:
         client:
           registration:
              messaging-client-oidc:
                 provider: spring 
                 client-id: messaging-client #客户端id
                 client-secret: secret # 客户端id
                 authorization-grant-type: authorization_code # 授权码模式
                 redirect-uri: "http://127.0.0.1:8080/login/oauth2/code/{registrationId}" # 这个是一个模板 {baseUrl}/login/oauth2/code/{registrationId} 官方说明：https://docs.spring.io/spring-security/reference/6.1-SNAPSHOT/servlet/oauth2/login/core.html
                 scope: openid, profile
                 client-name: messaging-client-oidc
           provider:
             spring:
               issuer-uri: http://localhost:9000 #
   ```` 
   

#### 服务启动顺序
**①demo-authorizationserver[授权服务]**

**②messages-resource[资源服务]**

**③demo-client[客户端]**

messages-resource[资源服务]和③demo-client[客户端]没有先后顺序，demo-client[客户端]依赖demo-authorizationserver[授权服务]的端点，否则启动抛异常


#### 看看效果吧
假如我们有这样的一个微服务：【网关服务】、【认证服务】、【业务服务】

我们访问【业务服务】是通过【网关服务】进行转发的，【网关服务】判断是否登录或者有权限，如果没有登录或者没有权限，就会重定向到【认证服务】的进行登录，登录成功后，【认证服务】把token返回给【网关服务】，【网关服务】会携带token去访问【业务服务】，这样就完成了整个认证和鉴权过程，然后token是存储在【网关服务】的，也没有暴露出来，是不是比较安全


![img_10.png](image/img_10.png)

demo-client可以把它看作我们的【网关服务】，demo-authorizationserver可以看作我们的【认证服务】，messages-resource可以看作【业务服务】，你这样去理解是否能够理解oauth2的这个流程了呢，

<video controls>
  <source src="video/oauth2_demo1.mp4" type="video/mp4">
</video>

先把以上这个流程和思路理解了，后面集成第三方登录（微信、qq等）能更好理解
