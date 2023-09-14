## 😄Spring Authorization Server (1) oauth2.1、oidc 1.0 概念初步认识和基于maven的demo源码

### Spring Authorization Server 是什么呢？

Spring Authorization Server是一个<span style="color:red;">**授权**</span>框架，替代已被废弃的Spring Security OAuth框架，提供OAuth 2.1和OpenID Connect 1.0规范以及其他相关规范的实现。它构建在Spring Security之上，为构建OpenID Connect 1.0 Identity Providers和OAuth2 Authorization Server产品提供了一个安全、轻量级和可定制的基础。

### OAuth 2.1 又是什么呢？

OAuth 2.1 是 OAuth 2.0 协议的更新版本，旨在提供更好的安全性和实用性。OAuth 2.1 修复了 OAuth 2.0 中的一些安全漏洞和缺陷，以使开发人员更容易实现安全的身份验证和授权流程。OAuth 2.1 保留了 OAuth 2.0 的核心概念，但在一些方面进行了细化和改进，以提供更清晰、更安全的授权框架

### OAuth 2.0 又是什么呢？

OAuth 2.0（Open Authorization 2.0）是一种开放标准的授权协议，用于允许第三方应用程序以受限的方式访问资源所有者（用户）的受保护资源，而无需共享用户的凭据。OAuth 2.0 设计用于在不暴露用户密码的情况下，使用户能够授权第三方应用访问他们在某个资源服务器上存储的资源。

* OAuth 2.0 的协议流程通常涉及以下角色：

  * 资源所有者（Resource Owner）：资源的拥有者，通常是用户。他们有权决定是否授权第三方应用访问他们的资源。
  * 客户端（Client）：第三方应用程序，希望访问资源所有者的资源。客户端通过向授权服务器进行请求来获取访问令牌。
  * 授权服务器（Authorization Server）：负责验证资源所有者的身份，并向客户端颁发访问令牌，前提是资源所有者已经授权。
  * 资源服务器（Resource Server）：存储资源的服务器，可以接受访问令牌并提供资源给客户端。
* OAuth 2.0 定义了几种不同的授权流程，以适应不同的使用情况，包括：

  * 授权码授权流程（Authorization Code Flow）
  * 隐式授权流程（Implicit Flow）
  * 密码授权流程（Password Credentials Flow）
  * 客户端凭证授权流程（Client Credentials Flow）
  * 设备授权流程（Device Flow）

每种授权流程都有其特定的用例和安全性考虑。OAuth 2.0 主要用于实现用户授权和认证，而 OpenID Connect 则是在 OAuth 2.0 基础上构建的，用于实现身份验证和提供用户信息的协议。这两者一起在构建安全的身份验证和授权系统时发挥重要作用。

### OpenID Connect (OIDC) 1.0 的理解

OpenID Connect（OIDC）1.0 是建立在 OAuth 2.0 协议之上的一种身份验证和用户信息传输协议。它允许应用程序验证用户的身份，并获取有关用户的基本信息，同时利用 OAuth 2.0 提供的授权机制来访问受保护的资源。

**主要特点和组成部分**

1. **身份验证（Authentication）**：OIDC 允许应用程序验证用户的身份。用户可以通过 OIDC 提供的机制进行登录，然后应用程序将收到一个 ID 令牌，证明用户已经通过身份验证。
2. **ID 令牌（ID Token）**：这是 OIDC 所引入的重要概念。ID 令牌是一个 JSON Web Token（JWT），其中包含有关用户身份的信息，如用户ID、姓名、电子邮件等。应用程序可以使用这个令牌来验证用户身份，避免了需要让用户提供用户名和密码。[到授权服务器获取token时，scope包含有openid是，会有id_token返回里面也包含了用户信息]
3. **用户信息端点（UserInfo Endpoint）**：OIDC 规范定义了一个用户信息端点，允许应用程序通过访问令牌获取有关用户的详细信息，如头像、地址等。[授权服务器上也有一个端点-/userinfo,当然每个授权服务器的端点命名都不同，[客户端的配置说明](https://docs.spring.io/spring-security/reference/6.1-SNAPSHOT/servlet/oauth2/login/core.html)]
4. **基于标准的扩展（Standard Extensions）**：OIDC 提供了一些扩展，以支持单点登录（Single Sign-On）和其他身份验证场景。例如，通过使用会话状态信息，用户可以在多个应用程序之间进行无缝的身份验证。
5. **与 OAuth 2.0 的结合**：OIDC 本质上是在 OAuth 2.0 的框架中添加了身份验证功能。它仍然使用 OAuth 2.0 的授权码、隐式、密码等流程，但添加了 ID 令牌和用户信息端点来支持身份验证和用户信息传递。

OpenID Connect 1.0 旨在通过在 OAuth 2.0 基础上添加身份验证和用户信息传递的功能，为应用程序提供更安全、更便利的用户身份验证和授权机制。这对于构建安全、可信的身份验证系统以及支持单点登录等功能非常重要。

### 准备工作
我们直接下载 spring-authorization-server 最新的源码（当前最新1.1.x），因为源码里面有demo，但是spring-authorization-server是基于gradle构建的，并不是基于maven构建的，如果没有配置gradle环境的，下面也为大家提供maven环境的demo，以便于直接上手

1. 👉 **[`spring-authorization-server官方文档`](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/index.html)**
2. 👉 **[`spring-security官方文档`](https://docs.spring.io/spring-security/reference/6.1-SNAPSHOT/servlet/oauth2/login/core.html)**
3. 👉 **[`spring-authorization-server源码(源码里面有demo)`](https://github.com/spring-projects/spring-authorization-server)**
4. 👉 **[基于maven的构建的spring-authorization-server源码demo](https://github.com/WatermelonPlanet/spring-authorization-server-master)**

**别再去百度了，关键时刻还是得看官方文档，也必须学会，虽然官方文档是社区人员维护的，对初学者不友好，可以结合源码和文档一起看，都有进步的，本人也是菜，但是要提升，必须学会看官方的文档，然后去研究**
