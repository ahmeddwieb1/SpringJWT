# SpringJWT

A learning project demonstrating how to implement full sign-in, sign-up, authorization, and authentication using Spring Boot and JWT (JSON Web Tokens).

## Project Overview

This project is designed to help you understand how to build a secure authentication and authorization mechanism in a Spring Boot application using JWT. It covers the core aspects of user registration, login, and protecting resources with JWT-based security.

- **Language:** Java
- **Framework:** Spring Boot
- **Authentication:** JWT (JSON Web Token)
- **Features:** Sign Up, Sign In, Authorization, Authentication

## Project Structure

The main Java source code is located under:
```
src/main/java/org/
```
Due to technical limitations, a detailed class listing is not shown here, but you will typically find:

- **Entities:** User and Role models
- **Controllers:** REST endpoints for authentication (sign-in, sign-up)
- **Services:** Business logic for user management and JWT handling
- **Security:** JWT token provider, filters, and security configuration

## Features

- User Registration (Sign Up)
- User Login (Sign In) with JWT token generation
- JWT-based request authentication and authorization
- Secure endpoints accessible only with valid JWT
- Spring Security integration

## Getting Started

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ahmeddwieb1/SpringJWT.git
   cd SpringJWT
   ```

2. **Configure application properties:**
   - Edit `src/main/resources/application.properties` to set up your database and JWT secrets.

3. **Build and run:**
   ```bash
   mvn spring-boot:run
   ```
   or use your favorite IDE.

4. **Testing the API:**
   - Use Postman to test registration and login endpoints.
   - Use the received JWT token to access protected endpoints.

## Endpoints Example

- `POST /api/auth/register` — Register a new user
- `POST /api/auth/login` — Authenticate user and receive a JWT token
- `GET /api/protected` — Example of a protected resource (requires JWT)

## Learning Goals

- Understand the flow of JWT Authentication in Spring Boot
- Learn how to secure RESTful APIs
- Practice structuring a Spring Boot project for security

## License

This project is for learning purposes and does not include a license.

---
**Author:** [ahmeddwieb1](https://github.com/ahmeddwieb1)
