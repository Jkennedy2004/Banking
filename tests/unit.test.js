const request = require('supertest');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const login = require('../src/login');
const database = require('../src/database');
const app = require('../src/app');

// Mock database module
jest.mock('../src/database');

describe('Unit Tests', () => {
  
  describe('Password Validation', () => {
    test('should validate strong passwords', () => {
      const strongPasswords = [
        'ValidPassword123!',
        'MySecure@Pass1',
        'Complex#Password9',
        'Str0ng&Password'
      ];

      strongPasswords.forEach(password => {
        const result = login.validatePassword(password);
        expect(result.valid).toBe(true);
        expect(result.message).toBe('Password is valid');
      });
    });

    test('should reject weak passwords', () => {
      const weakPasswords = [
        { password: 'short', reason: 'too short' },
        { password: 'nouppercase123!', reason: 'no uppercase' },
        { password: 'NOLOWERCASE123!', reason: 'no lowercase' },
        { password: 'NoNumbers!', reason: 'no numbers' },
        { password: 'NoSpecialChars123', reason: 'no special characters' }
      ];

      weakPasswords.forEach(({ password, reason }) => {
        const result = login.validatePassword(password);
        expect(result.valid).toBe(false);
        expect(result.message).toBeDefined();
      });
    });
  });

  describe('JWT Token Generation and Verification', () => {
    const testUser = {
      id: 1,
      email: 'test@example.com',
      role: 'user'
    };

    test('should generate valid JWT tokens', () => {
      const token = jwt.sign(
        testUser,
        process.env.JWT_SECRET || 'test-jwt-secret-key',
        { expiresIn: '1h' }
      );

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
    });

    test('should verify valid JWT tokens', () => {
      const token = jwt.sign(
        testUser,
        process.env.JWT_SECRET || 'test-jwt-secret-key',
        { expiresIn: '1h' }
      );

      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'test-jwt-secret-key');
      
      expect(decoded.id).toBe(testUser.id);
      expect(decoded.email).toBe(testUser.email);
      expect(decoded.role).toBe(testUser.role);
    });

    test('should reject tampered tokens', () => {
      let token = jwt.sign(
        testUser,
        process.env.JWT_SECRET || 'test-jwt-secret-key',
        { expiresIn: '1h' }
      );

      // Tamper with the token
      token = token.slice(0, -5) + 'tampered';

      expect(() => {
        jwt.verify(token, process.env.JWT_SECRET || 'test-jwt-secret-key');
      }).toThrow();
    });
  });

  describe('Password Hashing', () => {
    test('should hash passwords securely', async () => {
      const password = 'TestPassword123!';
      const hash = await bcrypt.hash(password, 12);

      expect(hash).toBeDefined();
      expect(hash).not.toBe(password);
      expect(hash.length).toBeGreaterThan(50);
      expect(hash.startsWith('$2a$12$')).toBe(true);
    });

    test('should verify correct passwords', async () => {
      const password = 'TestPassword123!';
      const hash = await bcrypt.hash(password, 12);
      
      const isValid = await bcrypt.compare(password, hash);
      expect(isValid).toBe(true);
    });

    test('should reject incorrect passwords', async () => {
      const correctPassword = 'TestPassword123!';
      const wrongPassword = 'WrongPassword123!';
      const hash = await bcrypt.hash(correctPassword, 12);
      
      const isValid = await bcrypt.compare(wrongPassword, hash);
      expect(isValid).toBe(false);
    });
  });

  describe('Authentication Module', () => {
    beforeEach(() => {
      jest.clearAllMocks();
    });

    test('should successfully authenticate valid user', async () => {
      const mockUser = {
        id: 1,
        email: 'test@example.com',
        password_hash: await bcrypt.hash('ValidPassword123!', 12),
        first_name: 'Test',
        last_name: 'User',
        status: 'active',
        role: 'user'
      };

      database.getUserByEmail.mockResolvedValue(mockUser);
      database.getFailedLoginAttempts.mockResolvedValue(0);
      database.clearFailedLoginAttempts.mockResolvedValue();
      database.logSuccessfulLogin.mockResolvedValue();

      const result = await login.authenticate('test@example.com', 'ValidPassword123!');

      expect(result.success).toBe(true);
      expect(result.token).toBeDefined();
      expect(result.user.email).toBe('test@example.com');
    });

    test('should fail authentication for non-existent user', async () => {
      database.getUserByEmail.mockResolvedValue(null);

      const result = await login.authenticate('nonexistent@example.com', 'password');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid credentials');
      expect(result.token).toBeUndefined();
    });

    test('should fail authentication for inactive user', async () => {
      const mockUser = {
        id: 1,
        email: 'test@example.com',
        password_hash: await bcrypt.hash('ValidPassword123!', 12),
        status: 'inactive'
      };

      database.getUserByEmail.mockResolvedValue(mockUser);

      const result = await login.authenticate('test@example.com', 'ValidPassword123!');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Account is not active');
    });

    test('should fail authentication for wrong password', async () => {
      const mockUser = {
        id: 1,
        email: 'test@example.com',
        password_hash: await bcrypt.hash('CorrectPassword123!', 12),
        status: 'active'
      };

      database.getUserByEmail.mockResolvedValue(mockUser);
      database.logFailedLogin.mockResolvedValue();

      const result = await login.authenticate('test@example.com', 'WrongPassword123!');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid credentials');
      expect(database.logFailedLogin).toHaveBeenCalled();
    });
  });

  describe('User Registration', () => {
    beforeEach(() => {
      jest.clearAllMocks();
    });

    test('should successfully register new user', async () => {
      database.getUserByEmail.mockResolvedValue(null); // User doesn't exist
      database.createUser.mockResolvedValue(123); // New user ID
      database.createAccount.mockResolvedValue(456); // New account ID

      const result = await login.register(
        'newuser@example.com',
        'ValidPassword123!',
        'New',
        'User'
      );

      expect(result.success).toBe(true);
      expect(result.userId).toBe(123);
      expect(database.createUser).toHaveBeenCalledWith({
        email: 'newuser@example.com',
        password_hash: expect.any(String),
        first_name: 'New',
        last_name: 'User',
        status: 'active',
        role: 'user'
      });
    });

    test('should reject registration for existing user', async () => {
      const existingUser = { id: 1, email: 'existing@example.com' };
      database.getUserByEmail.mockResolvedValue(existingUser);

      const result = await login.register(
        'existing@example.com',
        'ValidPassword123!',
        'Existing',
        'User'
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe('User already exists with this email');
      expect(database.createUser).not.toHaveBeenCalled();
    });

    test('should reject registration with weak password', async () => {
      database.getUserByEmail.mockResolvedValue(null);

      const result = await login.register(
        'test@example.com',
        'weakpass',
        'Test',
        'User'
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Password must');
      expect(database.createUser).not.toHaveBeenCalled();
    });
  });

  describe('Database Helper Functions', () => {
    test('should generate unique account numbers', () => {
      const accountNumber1 = database.generateAccountNumber();
      const accountNumber2 = database.generateAccountNumber();

      expect(accountNumber1).toMatch(/^ACC\d{12}$/);
      expect(accountNumber2).toMatch(/^ACC\d{12}$/);
      expect(accountNumber1).not.toBe(accountNumber2);
    });

    test('should generate secure random tokens', () => {
      const token1 = login.generateSecureToken();
      const token2 = login.generateSecureToken(16);

      expect(token1).toHaveLength(64); // 32 bytes = 64 hex chars
      expect(token2).toHaveLength(32); // 16 bytes = 32 hex chars
      expect(token1).not.toBe(token2);
      expect(token1).toMatch(/^[a-f0-9]+$/);
    });
  });

  describe('API Endpoints', () => {
    test('should return health status', async () => {
      const response = await request(app)
        .get('/health')
        .expect(200);

      expect(response.body.status).toBe('healthy');
      expect(response.body.service).toBe('banking-app');
      expect(response.body.timestamp).toBeDefined();
    });

    test('should return 404 for non-existent endpoints', async () => {
      const response = await request(app)
        .get('/non-existent-endpoint')
        .expect(404);

      expect(response.body.error).toBe('Resource not found');
    });

    test('should validate request body for login', async () => {
      const invalidRequests = [
        { email: 'invalid-email', password: 'ValidPassword123!' },
        { email: 'test@example.com', password: 'weak' },
        { email: '', password: 'ValidPassword123!' },
        { password: 'ValidPassword123!' }, // Missing email
        { email: 'test@example.com' } // Missing password
      ];

      for (const invalidRequest of invalidRequests) {
        const response = await request(app)
          .post('/api/auth/login')
          .send(invalidRequest)
          .expect(400);

        expect(response.body.error).toBe('Validation failed');
        expect(response.body.details).toBeDefined();
      }
    });

    test('should validate request body for registration', async () => {
      const invalidRequests = [
        { 
          email: 'test@example.com',
          password: 'ValidPassword123!',
          firstName: '', // Empty first name
          lastName: 'User'
        },
        {
          email: 'test@example.com',
          password: 'ValidPassword123!',
          firstName: 'Test',
          lastName: 'A' // Too short last name
        }
      ];

      for (const invalidRequest of invalidRequests) {
        const response = await request(app)
          .post('/api/auth/register')
          .send(invalidRequest)
          .expect(400);

        expect(response.body.error).toBe('Validation failed');
      }
    });
  });

  describe('Error Handling', () => {
    test('should handle database connection errors gracefully', async () => {
      database.getUserByEmail.mockRejectedValue(new Error('Database connection failed'));

      const result = await login.authenticate('test@example.com', 'password');

      expect(result.success).toBe(false);
      expect(result.error).toBe('Authentication failed');
    });

    test('should handle registration errors gracefully', async () => {
      database.getUserByEmail.mockResolvedValue(null);
      database.createUser.mockRejectedValue(new Error('Database error'));

      const result = await login.register(
        'test@example.com',
        'ValidPassword123!',
        'Test',
        'User'
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe('Registration failed');
    });
  });

  describe('Input Sanitization', () => {
    test('should normalize email addresses', async () => {
      database.getUserByEmail.mockResolvedValue(null);
      database.createUser.mockResolvedValue(123);
      database.createAccount.mockResolvedValue(456);

      await login.register(
        'Test@Example.Com',
        'ValidPassword123!',
        'Test',
        'User'
      );

      expect(database.createUser).toHaveBeenCalledWith(
        expect.objectContaining({
          email: 'test@example.com' // Should be normalized to lowercase
        })
      );
    });
  });
});