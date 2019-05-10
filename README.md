# spring-boot-2-keycloak
Securing spring boot application with keycloak 


# Versions -
  <b>Spring Boot</b> - 2.1.4 <br/>
  <b>Keycloak</b> - 6.1.0<br/>
  <b>JDK</b> - 11<br/>


# Prerequisite Softwares
  <b>docker</b>

# How to run ?
1. First start the keycloak either using docker or as standlone service and make sure it's running on port 8080<br/>
2. Create <b>demo-api</b> client in realm <b>demo</b> <br/>
3. Add two roles USER & ADMIN respectively and assign few users either of these two roles <br/>
4. Clone the project and build the docker image using <b> mvn clean install && docker build -t demo . </b>
5. Run the application using -<br/>
<b>docker run -p 8090:8090 --name demo demo</b><br/>
6. Try accessing the application on <b>http://localhost:8090/user/hello</b> and <b>http://localhost:8090/admin/hello</b> for users with corresponding roles
