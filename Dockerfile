FROM maven:3.9.11-eclipse-temurin-25 AS build
WORKDIR /workspace

COPY pom.xml .
RUN mvn -DskipTests dependency:go-offline -B

COPY src src
RUN mvn -DskipTests package -B

FROM dhi.io/eclipse-temurin:25-debian13
WORKDIR /app
COPY --from=build /workspace/target/*.jar app.jar
USER nonroot
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
