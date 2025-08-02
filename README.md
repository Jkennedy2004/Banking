# Banking Application

A secure, production-ready banking application built with Node.js, featuring comprehensive security measures, automated testing, and CI/CD pipeline.

## 🏦 Features

- **Secure Authentication**: JWT-based authentication with bcrypt password hashing
- **Account Management**: Balance inquiries and transaction history
- **Fund Transfers**: Secure money transfers between accounts
- **Security First**: Multiple layers of security protection
- **Rate Limiting**: Protection against brute force attacks
- **Input Validation**: Comprehensive input sanitization and validation
- **Audit Logging**: Complete audit trail of all transactions and login attempts

## 🔒 Security Features

- **OWASP Compliance**: Following OWASP Top 10 security practices
- **Helmet.js**: Security headers protection
- **SQL Injection Prevention**: Parameterized queries and input validation
- **XSS Protection**: Input sanitization and CSP headers
- **Rate Limiting**: Request rate limiting and login attempt throttling
- **Session Security**: Secure JWT token management
- **Password Security**: Strong password requirements and secure hashing
- **CORS Protection**: Configurable CORS policies
- **Security Headers**: Comprehensive HTTP security headers

## 🚀 Quick Start

### Prerequisites

- Node.js 18.x or higher
- MySQL 8.0 or higher
- Docker (optional)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/company/banking-app.git
cd banking-app
```

2. **Install dependencies**
```bash
npm install
```

3. **Set up environment variables**
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Set up the database**
```bash
# Create MySQL database
mysql -u root -p -e "CREATE DATABASE banking_db;"
mysql -u root -p -e "CREATE USER 'banking_user'@'localhost' IDENTIFIED BY 'secure_password';"
mysql -u root -p -e "GRANT ALL PRIVILEGES ON banking_db.* TO 'banking_user'@'localhost';"

# Initialize database tables
npm run init-db
```

5. **Start the application**
```bash
# Development mode
npm run dev

# Production mode
npm start
```

## 🐳 Docker Deployment

### Build and run with Docker

```bash
# Build the image
npm run build

# Run the container
docker run -d \
  --name banking-app \
  -p 3000:3000 \
  -e DB_HOST=your-db-host \
  -e DB_USER=banking_user \
  -e DB_PASSWORD=secure_password \
  -e DB_NAME=banking_db \
  -e JWT_SECRET=your-super-secret-jwt-key \
  banking-app:latest
```

### Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f banking-app

# Stop services
docker-compose down
```

## 🧪 Testing

### Run all tests
```bash
npm test
```

### Run specific test suites
```bash
# Unit tests
npm run test:unit

# Security tests
npm run test:security

# Coverage report
npm run test -- --coverage
```

### Security Testing
```bash
# Static analysis with ESLint
npm run lint

# Dependency vulnerability scan
npm run security:snyk

# OWASP dependency check
npm audit

# SonarQube analysis
npm run sonar
```

## 📡 API Documentation

### Authentication Endpoints

#### POST `/api/auth/login`
Authenticate user and receive JWT token.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response:**
```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6...",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe"
  }
}
```

#### POST `/api/auth/register`
Register a new user account.

**Request:**
```json
{
  "email": "newuser@example.com",
  "password": "SecurePassword123!",
  "firstName": "Jane",
  "lastName": "Smith"
}
```

### Account Endpoints

All account endpoints require authentication header:
```
Authorization: Bearer <JWT_TOKEN>
```

#### GET `/api/account/balance`
Get current account balance.

**Response:**
```json
{
  "balance": 1500.75,
  "currency": "USD"
}
```

#### GET `/api/account/transactions`
Get transaction history.

**Query Parameters:**
- `limit` (optional): Number of transactions (default: 10)
- `offset` (optional): Pagination offset (default: 0)

**Response:**
```json
{
  "transactions": [
    {
      "id": 1,
      "type": "debit",
      "amount": 100.00,
      "description": "Transfer to ACC87654321",
      "balance_after": 1400.75,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "count": 1
}
```

#### POST `/api/account/transfer`
Transfer funds to another account.

**Request:**
```json
{
  "toAccount": "ACC87654321",
  "amount": 100.00,
  "description": "Payment for services"
}
```

**Response:**
```json
{
  "message": "Transfer completed successfully",
  "transactionId": 123
}
```

## 🏗️ Architecture

### Project Structure
```
banking-app/
├── src/
│   ├── app.js          # Main application
│   ├── login.js        # Authentication logic
│   └── database.js     # Database operations
├── tests/
│   ├── security.test.js # Security tests
│   └── unit.test.js    # Unit tests
├── docker/
│   └── Dockerfile      # Container configuration
├── security/
│   ├── sonar-config.properties
│   └── snyk-config.json
└── .github/workflows/  # CI/CD pipelines
```

### Database Schema

#### Users Table
```sql
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100) NOT NULL,
  status ENUM('active', 'inactive', 'suspended') DEFAULT 'active',
  role ENUM('user', 'admin') DEFAULT 'user',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

#### Accounts Table
```sql
CREATE TABLE accounts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  account_number VARCHAR(20) UNIQUE NOT NULL,
  account_type ENUM('checking', 'savings') DEFAULT 'checking',
  balance DECIMAL(15,2) DEFAULT 0.00,
  status ENUM('active', 'inactive', 'closed') DEFAULT 'active',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file with the following variables:

```env
# Application
NODE_ENV=production
PORT=3000

# Database
DB_HOST=localhost
DB_PORT=3306
DB_USER=banking_user
DB_PASSWORD=secure_password
DB_NAME=banking_db
DB_SSL=false

# Security
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_EXPIRES_IN=24h

# CORS
ALLOWED_ORIGINS=https://your-frontend-domain.com,https://admin.your-domain.com

# External Services
SNYK_TOKEN=your-snyk-token
SONAR_TOKEN=your-sonar-token
```

### Security Configuration

The application includes multiple security configurations:

1. **Helmet.js** - Security headers
2. **Rate Limiting** - Request throttling
3. **CORS** - Cross-origin resource sharing
4. **Input Validation** - Request validation and sanitization
5. **Authentication** - JWT token validation
6. **Password Policy** - Strong password requirements

## 🔄 CI/CD Pipeline

The project includes comprehensive GitHub Actions workflows:

### Main Pipeline (`pipeline.yml`)
- Code quality analysis (ESLint, SonarQube)
- Security scanning (Snyk, OWASP)
- Unit and integration testing
- Docker build and container scanning
- Automated deployment to staging/production

### Security Pipeline (`security.yml`)
- Daily security scans
- SAST (Static Application Security Testing)
- DAST (Dynamic Application Security Testing)
- Dependency vulnerability scanning
- Container security analysis
- Infrastructure security checks

### Pipeline Features
- **Parallel execution** for faster builds
- **Security gates** preventing vulnerable deployments
- **Automated notifications** to Slack/Teams
- **Artifact management** for reports and builds
- **Environment-specific deployments**

## 📊 Monitoring and Logging

### Application Monitoring
- Health check endpoint (`/health`)
- Winston logging for structured logs
- Performance metrics collection
- Error tracking and alerting

### Security Monitoring
- Failed login attempt tracking
- Rate limiting violations
- Suspicious activity detection
- Audit trail for all transactions

### Log Formats
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "info",
  "message": "User login successful",
  "userId": 123,
  "email": "user@example.com",
  "ip": "192.168.1.1",
  "userAgent": "Mozilla/5.0..."
}
```

## 🛡️ Security Best Practices

### Implemented Security Measures

1. **Authentication & Authorization**
   - JWT-based stateless authentication
   - Role-based access control
   - Password complexity requirements
   - Account lockout after failed attempts

2. **Data Protection**
   - Encryption at rest and in transit
   - Sensitive data masking in logs
   - Input validation and sanitization
   - SQL injection prevention

3. **Network Security**
   - HTTPS enforcement
   - Security headers (HSTS, CSP, etc.)
   - CORS policy configuration
   - Rate limiting and DDoS protection

4. **Application Security**
   - Regular dependency updates
   - Vulnerability scanning
   - Code quality analysis
   - Security testing automation

### Security Checklist

- [ ] Regular security dependency updates
- [ ] Periodic penetration testing
- [ ] Security incident response plan
- [ ] Employee security training
- [ ] Regular backup and disaster recovery testing
- [ ] Compliance audit (PCI DSS, SOX, etc.)

## 🤝 Contributing

### Development Workflow

1. **Fork the repository**
2. **Create a feature branch**
```bash
git checkout -b feature/new-feature
```

3. **Make your changes**
4. **Run tests**
```bash
npm test
npm run lint
npm run security:snyk
```

5. **Commit your changes**
```bash
git commit -m "feat: add new security feature"
```

6. **Push to your fork**
```bash
git push origin feature/new-feature
```

7. **Create a Pull Request**

### Code Standards

- Follow ESLint configuration
- Write comprehensive tests
- Update documentation
- Follow security best practices
- Use conventional commit messages

### Security Guidelines

- Never commit sensitive information
- Follow OWASP security guidelines
- Validate all inputs
- Use parameterized queries
- Implement proper error handling
- Follow principle of least privilege

## 📋 Deployment

### Production Deployment Checklist

- [ ] Environment variables configured
- [ ] Database migrations applied
- [ ] SSL certificates installed
- [ ] Monitoring and alerting configured
- [ ] Backup strategy implemented
- [ ] Security scanning completed
- [ ] Performance testing done
- [ ] Documentation updated

### Scaling Considerations

- **Horizontal Scaling**: Load balancer with multiple app instances
- **Database Scaling**: Read replicas for query optimization
- **Caching**: Redis for session management and caching
- **CDN**: Static asset delivery optimization
- **Monitoring**: Comprehensive application and infrastructure monitoring

## 📞 Support

### Getting Help

- **Documentation**: Check this README and inline code comments
- **Issues**: Create a GitHub issue for bugs or feature requests
- **Security**: Email security@banking-app.com for security issues
- **General**: Contact team@banking-app.com for general inquiries

### Troubleshooting

#### Common Issues

1. **Database Connection Failed**
   - Check database credentials in `.env`
   - Verify database server is running
   - Check network connectivity

2. **JWT Token Invalid**
   - Verify JWT_SECRET is set correctly
   - Check token expiration
   - Ensure consistent secret across instances

3. **Rate Limiting Triggered**
   - Check request frequency
   - Verify IP whitelisting if needed
   - Review rate limit configuration

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **OWASP** for security guidelines and best practices
- **Node.js Security Working Group** for security recommendations
- **Banking Industry** standards and compliance requirements
- **Open Source Community** for the excellent libraries and tools

---

**⚠️ Security Notice**: This application handles sensitive financial data. Always follow security best practices, keep dependencies updated, and conduct regular security audits in production environments.