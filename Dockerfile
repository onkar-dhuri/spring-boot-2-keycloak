FROM openjdk:11.0.1-jdk-oracle
MAINTAINER onkar.dhuri@gmail.com

ARG JAR_FILE_PATH=target/spring-boot-2-keycloak-0.0.1-SNAPSHOT.jar
ENV JAR_FILE_NAME=spring-boot-2-keycloak-0.0.1-SNAPSHOT.jar

ARG JAR_CONFIG

ADD  ${JAR_FILE_PATH}  ${JAR_FILE_NAME}

EXPOSE 8090

CMD java  ${JAR_CONFIG} -jar ${JAR_FILE_NAME}
