FROM openjdk:17-ea-11-jdk-slim
VOLUME /tmp
COPY target/emsapigateway-service-1.0.jar EmsapigatewayService.jar
ENTRYPOINT ["java", "-jar", "EmsapigatewayService.jar"]