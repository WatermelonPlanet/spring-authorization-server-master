# 😄Spring Authorization Server (5) RegisteredClientRepository、UserDetailsService、UserDetails扩展

* [RegisteredClientRepository](###RegisteredClientRepository)
* [UserDetailsService](###UserDetailsService)
* [UserDetails](###UserDetails)

### RegisteredClientRepository

**RegisteredClientRepository** 的实现类**JdbcRegisteredClientRepository**

`AuthorizationServerConfig`中 `RegisteredClientRepository`的实例化

````java
@Bean
public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate){
    //......
     // Save registered client's in db as if in-memory
     JdbcRegisteredClientRepository registeredClientRepository=new JdbcRegisteredClientRepository(jdbcTemplate);

     return registeredClientRepository;
}
````

`RegisteredClientRepository`接口源码

````java
public interface RegisteredClientRepository {
  
	void save(RegisteredClient registeredClient);

	@Nullable
	RegisteredClient findById(String id);

	@Nullable
	RegisteredClient findByClientId(String clientId);
}
````

**MybatisRegisteredClientRepository**基于mybatis-plus的自定义实现存储和查询

````java
@Component
@RequiredArgsConstructor
public class MybatisRegisteredClientRepository implements RegisteredClientRepository {
    private static final String CLIENT_ID_NOT_EXIST_ERROR_CODE = "client not exist";
    private static final String ZONED_DATETIME_ZONE_ID = "Asia/Shanghai";
    private final SysRegisteredClientService sysRegisteredClientService;
    @Override
    public void save(RegisteredClient registeredClient) {
        SysRegisteredClientDto sysRegisteredClientDto = new SysRegisteredClientDto();
        sysRegisteredClientDto.setClientId(registeredClient.getClientId());
        sysRegisteredClientDto.setClientName(registeredClient.getClientName());
        sysRegisteredClientDto.setClientSecret(registeredClient.getClientSecret());
        if (registeredClient.getClientIdIssuedAt() != null) {
            sysRegisteredClientDto.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt().atZone(ZoneId.of("Asia/Shanghai")).toLocalDateTime());
        }
        if (registeredClient.getClientSecretExpiresAt() != null) {
            sysRegisteredClientDto.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt().atZone(ZoneId.of("Asia/Shanghai")).toLocalDateTime());
        }
        sysRegisteredClientDto.setClientAuthenticationMethods(registeredClient.getClientAuthenticationMethods().stream().map(ClientAuthenticationMethod::getValue).collect(Collectors.toSet()));
        sysRegisteredClientDto.setAuthorizationGrantTypes(registeredClient.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue).collect(Collectors.toSet()));
        sysRegisteredClientDto.setRedirectUris(registeredClient.getRedirectUris());
        sysRegisteredClientDto.setPostLogoutRedirectUris(registeredClient.getPostLogoutRedirectUris());
        sysRegisteredClientDto.setScopes(registeredClient.getScopes());
        sysRegisteredClientDto.setTokenSettings(registeredClient.getTokenSettings().getSettings());
        sysRegisteredClientDto.setClientSettings(registeredClient.getClientSettings().getSettings());
        sysRegisteredClientService.saveClient(sysRegisteredClientDto);
    }
    @Override
    public RegisteredClient findById(String id) {
        SysRegisteredClientDto sysRegisteredClientDetailVo = sysRegisteredClientService.getOneById(id);
        if (sysRegisteredClientDetailVo == null) {
            throw new ClientAuthorizationException(new OAuth2Error(CLIENT_ID_NOT_EXIST_ERROR_CODE,
                    "Authorization client table data id not exist: " + id, null),
                    id);
        }
        return sysRegisteredClientDetailConvert(sysRegisteredClientDetailVo);
    }
    @Override
    public RegisteredClient findByClientId(String clientId) {
        SysRegisteredClientDto sysRegisteredClientDto = sysRegisteredClientService.getOneByClientId(clientId);
        if (sysRegisteredClientDto == null) {
            return null;
        }
        return sysRegisteredClientDetailConvert(sysRegisteredClientDto);
    }
    private RegisteredClient sysRegisteredClientDetailConvert(SysRegisteredClientDto sysRegisteredClientDto) {
        RegisteredClient.Builder builder = RegisteredClient
                .withId(sysRegisteredClientDto.getId())
                .clientId(sysRegisteredClientDto.getClientId())
                .clientSecret(sysRegisteredClientDto.getClientSecret())
                .clientIdIssuedAt(Optional.ofNullable(sysRegisteredClientDto.getClientIdIssuedAt())
                        .map(d -> d.atZone(ZoneId.of(ZONED_DATETIME_ZONE_ID)).toInstant())
                        .orElse(null))
                .clientSecretExpiresAt(Optional.ofNullable(sysRegisteredClientDto.getClientSecretExpiresAt())
                        .map(d -> d.atZone(ZoneId.of(ZONED_DATETIME_ZONE_ID)).toInstant())
                        .orElse(null))
                .clientName(sysRegisteredClientDto.getClientName())
                .clientAuthenticationMethods(c ->
                        c.addAll(sysRegisteredClientDto.getClientAuthenticationMethods()
                                .stream().map(ClientAuthenticationMethod::new).collect(Collectors.toSet()))
                ).authorizationGrantTypes(a ->
                        a.addAll(sysRegisteredClientDto.getAuthorizationGrantTypes()
                                .stream().map(AuthorizationGrantType::new).collect(Collectors.toSet()))
                ).redirectUris(r -> r.addAll(sysRegisteredClientDto.getRedirectUris()))
                .postLogoutRedirectUris(p -> p.addAll(sysRegisteredClientDto.getPostLogoutRedirectUris()))
                .scopes(s -> s.addAll(sysRegisteredClientDto.getScopes()))
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build());// requireAuthorizationConsent(true) 不设置 授权页不会显示
//                .tokenSettings(TokenSettings.builder().build());
        //todo clientSettings和 tokenSettings 根据需要后续自行修改
//                .clientSettings(ClientSettings.withSettings(sysRegisteredClientDetailVo.getClientSettings()).build());
        return builder.build();
    }
}
````

最后`AuthorizationServerConfig`中 删除`RegisteredClientRepository`的实例


### UserDetailsService

**UserDetailsService**的实现**InMemoryUserDetailsManager**

`DefaultSecurityConfig`中的`UserDetailsService`实例和内存存储用户数据

````java
@Bean
public UserDetailsService users(){
        UserDetails user=User.withDefaultPasswordEncoder()
        .username("user1")
        .password("password")
        .roles("USER")
        .build();
        return new InMemoryUserDetailsManager(user);
}
````

`UserDetailsService` 源码，这个里面只有 *loadUserByUsername(String username)* 一个方法

````java
public interface UserDetailsService {
	UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
````

**UserDetailsServiceImpl**是基于基于mybatis-plus做查询的实现类

````java
@Component
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final SysUserService sysUserService;

    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //如今这个世界 我们肯定都用手机号登录的了
        SysUserDetailDto sysUser = sysUserService.findOneByPhone(username);
        if (sysUser == null) {
            throw new UsernameNotFoundException("手机号：" + username + "未注册!");
        }
        //todo 后续可自行修改和完善
        List<GrantedAuthority> authorityList = new ArrayList<>();
        SysUserDto sysUserDto = new SysUserDto();
        sysUserDto.setUsername(username);
        sysUserDto.setAuthorities(authorityList);
        sysUserDto.setId(sysUser.getId());
        sysUserDto.setAvatar(sysUser.getAvatar());
        sysUserDto.setPassword(passwordEncoder.encode(sysUser.getPassword()));
        sysUserDto.setStatus(sysUser.getStatus());
        sysUserDto.setPhone(sysUser.getPhone());
        return sysUserDto;
    }
}
````

最后在`DefaultSecurityConfig` 中注入 `PasswordEncoder`实例，加密和解密需要，把`UserDetailsService`的实例

````java
@Bean
public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
}
````

````java
public static PasswordEncoder createDelegatingPasswordEncoder() {
		String encodingId = "bcrypt";
		Map<String, PasswordEncoder> encoders = new HashMap<>();
		encoders.put(encodingId, new BCryptPasswordEncoder());
		encoders.put("ldap", new org.springframework.security.crypto.password.LdapShaPasswordEncoder());
		encoders.put("MD4", new org.springframework.security.crypto.password.Md4PasswordEncoder());
		encoders.put("MD5", new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("MD5"));
		encoders.put("noop", org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance());
		encoders.put("pbkdf2", Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_5());
		encoders.put("pbkdf2@SpringSecurity_v5_8", Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8());
		encoders.put("scrypt", SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1());
		encoders.put("scrypt@SpringSecurity_v5_8", SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8());
		encoders.put("SHA-1", new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("SHA-1"));
		encoders.put("SHA-256",
				new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("SHA-256"));
		encoders.put("sha256", new org.springframework.security.crypto.password.StandardPasswordEncoder());
		encoders.put("argon2", Argon2PasswordEncoder.defaultsForSpringSecurity_v5_2());
		encoders.put("argon2@SpringSecurity_v5_8", Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8());
		return new DelegatingPasswordEncoder(encodingId, encoders);
	}
````

`PasswordEncoder` 默认是 **bcrypt** 对应的就是 BCryptPasswordEncoder，如果要替换加密/解密方式，有如下两种解决方案

①：重新创建一个授权类型（后面会单独写一遍如何扩展授权类型[短信登录扩展]）

②：继承 `DaoAuthenticationProvider` 重写 *additionalAuthenticationChecks()*方法，目的是重现注入 `passwordEncoder`后再进行密码匹配


#### UserDetails 扩展

````java
/**
 * 用户扩展字段（不序列化会抛异常(@JsonSerialize,Serializable),不将扩展字段忽略也会有异常[@JsonIgnoreProperties(ignoreUnknown = true)] 是因为 security 内部实现的原因）
 * @author byh
 * @date 2023-09-15
 * @description
 */
@Data
@JsonSerialize
@JsonIgnoreProperties(ignoreUnknown = true)
public class SysUserDto implements UserDetails, Serializable {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
    /**
     * id
     */
    private  Long id;
    /**
     * 手机号(未加密)
     */
    private  String phone;
    /**
     * 用户名
     */
    private  String username;
    /**
     * 用户名
     */
    private  String password;
    /**
     * 头像
     */
    private  String avatar;
    /**
     * 账号状态(0:无效；1:有效)
     */
    private  Integer status;
    /**
     * 权限
     */
    private Collection<GrantedAuthority> authorities;


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

````

MybatisRegisteredClientRepository.java 链接：https://github.com/WatermelonPlanet/watermelon-cloud/blob/master/watermelon-authorization/watermelon-authorization-server/src/main/java/com/watermelon/authorization/builtin/impl/MybatisRegisteredClientRepository.java

UserDetailsServiceImpl.java 链接：https://github.com/WatermelonPlanet/watermelon-cloud/blob/master/watermelon-authorization/watermelon-authorization-server/src/main/java/com/watermelon/authorization/builtin/impl/UserDetailsServiceImpl.java

SysUserDto.java 链接 https://github.com/WatermelonPlanet/watermelon-cloud/blob/master/watermelon-authorization/watermelon-authorization-server/src/main/java/com/watermelon/authorization/builtin/dto/SysUserDto.java

完整的项目链接[https://github.com/WatermelonPlanet/watermelon-cloud]