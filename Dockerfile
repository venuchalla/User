
FROM eclipse-temurin:19-jre

WORKDIR /app

# added step to copy jar from target to app jar
COPY target/user-0.0.1-SNAPSHOT.jar app.jar

ENV SPRING_PROFILES_ACTIVE=prod

EXPOSE 8082

ENTRYPOINT ["java", "-jar", "app.jar"]

