# Build reprodutível dos ZIPs dos Lambdas (specs 02 e 03). NÃO é a imagem de runtime: o SnapStart proíbe
# imagem de container, então os artefatos implantados são os JARs com dependências (ZIP).
#
#   docker build --target artifact --output type=local,dest=./dist .
#   -> ./dist/auth-function.jar e ./dist/authorizer-function.jar
#
# Os testes rodam no job build-test (precisam de Docker para o Testcontainers); aqui só se empacota.
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml ./
COPY auth-function/pom.xml auth-function/pom.xml
COPY authorizer-function/pom.xml authorizer-function/pom.xml
# Camada de dependências em cache: só invalida quando um pom muda.
RUN mvn -B -q dependency:go-offline
COPY auth-function/src auth-function/src
COPY authorizer-function/src authorizer-function/src
RUN mvn -B -q package -DskipTests

FROM scratch AS artifact
COPY --from=build /src/auth-function/target/auth-function.jar /auth-function.jar
COPY --from=build /src/authorizer-function/target/authorizer-function.jar /authorizer-function.jar
