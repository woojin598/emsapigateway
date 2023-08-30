FROM openjdk:11-jdk
WORKDIR /app
COPY target/*.jar app.jar
CMD ["java", "-Dspring.profiles.active=prod", "-jar", "app.jar"]