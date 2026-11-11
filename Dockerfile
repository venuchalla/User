FROM eclipse-temurin:21-jre

WORKDIR /app

COPY target/user-*.jar /app/app.jar

EXPOSE 8082

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
