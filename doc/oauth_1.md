## Spring Authorization Server (1)

**关于oauth2相关的概念本栏没有，可以去参考其他博主的文章，此栏只记录了Spring Authorization Server的一些原理和如何去扩展**

1.👉 **Spring Authorization Server 官方文档:https://docs.spring.io/spring-authorization-server/docs/current/reference/html/index.html**

2.👉 下载源码(源码里面有demo) https://github.com/spring-projects/spring-authorization-server

* 运行环境要求
  * jdk17
  * idea版本有要求（建议2022版本以上的，里面需要kotlin的插件版本要求是1.6以上的）
    ````java
      //可能运行时出现如下异常
      Exception in thread "main" java.lang.NoClassDefFoundError: kotlin/Result
    ````
  * idea中的 gradle也需要设置jdk版本 不是出现无效jdk的问题(基于maven的就跳过)
  * gradle(spring项目都是gradle构建、并没有采用maven) 提供了一个基于maven的最原始的demo：https://github.com/WatermelonPlanet/spring-authorization-server-demo/tree/master/original-demo


3.👉 运行demo
