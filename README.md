# Spring Security TagLibs for JSF 

This project is based on **taglib-jsf20-spring-3** developed by Dominik Dorn - http://www.dominikdorn.com/. You can find original project here: https://code.google.com/p/spring-security-facelets-taglib

I have updated sources to support Spring Security 4.x and JSF 2.2

You can use this project using jitPack maven repository. Add this to your `pom.xml`

    <repository>
      <id>jitpack.io</id>
      <url>https://jitpack.io</url>
    </repository>

And then you can use this dependency:

    <dependency>
      <groupId>com.github.malaguna</groupId>
      <artifactId>springsec-jsftl</artifactId>
      <version>-SNAPSHOT</version>
    </dependency>

You can change `version` literal to fit the name of any of the released tags of the project.
