FROM amazoncorretto:17-alpine-jdk
ENV JAVA_TOOL_OPTIONS -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8084
COPY target/*.jar jwt-auth-server.jar
ENTRYPOINT ["java", "-jar", "/jwt-auth-server.jar"]
