# Build reprodutível do ZIP do Lambda (spec 02 §3). NÃO é a imagem de runtime: o SnapStart proíbe
# imagem de container, então o artefato implantado é o JAR com dependências (ZIP).
#
#   docker build --target artifact --output type=local,dest=./dist .
#   -> ./dist/auth-function.jar
#
# Os testes rodam no job build-test (precisam de Docker para o Testcontainers); aqui só se empacota.
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml ./
COPY auth-function/pom.xml auth-function/pom.xml
# Camada de dependências em cache: só invalida quando um pom muda.
RUN mvn -B -q -pl auth-function -am dependency:go-offline
COPY auth-function/src auth-function/src
RUN mvn -B -q -pl auth-function -am package -DskipTests

FROM scratch AS artifact
COPY --from=build /src/auth-function/target/auth-function.jar /auth-function.jar
