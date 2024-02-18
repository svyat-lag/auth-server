FROM eclipse-temurin:17-jdk-alpine
WORKDIR /opt/app
COPY .mvn .mvn
COPY mvnw ./
COPY pom.xml ./
RUN ./mvnw dependency:go-offline
COPY ./src ./src
RUN ./mvnw clean install
ENTRYPOINT ["java", "-jar", "/opt/app/target/*.jar"]
