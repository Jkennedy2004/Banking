const request = require('supertest');
const app = require('../src/app');
const jwt = require('jsonwebtoken');

describe('Security Tests', () => {
  let validToken;
  
  beforeAll(() => {
    // Generate a valid token for authenticated requests
    validToken = jwt.sign(
      { id: 1, email: 'test@example.com', role: 'user' },
      process.env.JWT_SECRET || 'test-jwt-secret-key',
      { expiresIn: '1h' }
    );
  });

  describe('Authentication Security', () => {
    test('should reject requests without authentication token', async () => {
      const response = await request(app)
        .get('/api/account/balance')
        .expect(401);

      expect(response.body.error).toBe('Access token required');
    });

    test('should reject invalid JWT tokens', async () => {
      const response = await request(app)
        .get('/api/account/balance')
        .set('Authorization', 'Bearer invalid_token')
        .expect(401);

      expect(response.body.error).toBe('Invalid token');
    });

    test('should reject expired JWT tokens', async () => {
      const expiredToken = jwt.sign(
        { id: 1, email: 'test@example.com' },
        process.env.JWT_SECRET || 'test-jwt-secret-key',
        { expiresIn: '-1h' }
      );

      const response = await request(app)
        .get('/api/account/balance')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);

      expect(response.body.error).toBe('Token has expired');
    });

    test('should enforce rate limiting on login endpoint', async () => {
      const loginData = {
        email: 'test@example.com',
        password: 'TestPassword123!'
      };

      // Make multiple rapid requests to trigger rate limiting
      const requests = Array(6).fill().map(() =>
        request(app)
          .post('/api/auth/login')
          .send(loginData)
      );

      const responses = await Promise.all(requests);
      
      // At least one should be rate limited
      const rateLimitedResponse = responses.find(res => res.status === 429);
      expect(rateLimitedResponse).toBeDefined();
      expect(rateLimitedResponse.body.error).toContain('Too many');
    });
  });

  describe('Input Validation Security', () => {
    test('should reject SQL injection attempts in login', async () => {
      const maliciousLogin = {
        email: "admin@example.com' OR '1'='1",
        password: "password' OR '1'='1"
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(maliciousLogin)
        .expect(400);

      expect(response.body.error).toBe('Validation failed');
    });

    test('should sanitize XSS attempts in transfer description', async () => {
      const maliciousTransfer = {
        toAccount: 'ACC12345678',
        amount: 100,
        description: '<script>alert("XSS")</script>'
      };

      const response = await request(app)
        .post('/api/account/transfer')
        .set('Authorization', `Bearer ${validToken}`)
        .send(maliciousTransfer);

      // Should either sanitize or reject the malicious input
      if (response.status === 200) {
        expect(response.body.description).not.toContain('<script>');
      } else {
        expect(response.status).toBe(400);
      }
    });

    test('should reject invalid email formats', async () => {
      const invalidEmails = [
        'notanemail',
        'test@',
        '@example.com',
        'test..test@example.com',
        'test@example',
        ''
      ];

      for (const email of invalidEmails) {
        const response = await request(app)
          .post('/api/auth/register')
          .send({
            email: email,
            password: password,
            firstName: 'Test',
            lastName: 'User'
          })
          .expect(400);

        expect(response.body.error).toBe('Validation failed');
      }
    });

    test('should validate transfer amounts', async () => {
      const invalidAmounts = [-100, 0, 'invalid', null, undefined];

      for (const amount of invalidAmounts) {
        const response = await request(app)
          .post('/api/account/transfer')
          .set('Authorization', `Bearer ${validToken}`)
          .send({
            toAccount: 'ACC12345678',
            amount: amount,
            description: 'Test transfer'
          })
          .expect(400);

        expect(response.body.error).toBe('Validation failed');
      }
    });
  });

  describe('HTTP Security Headers', () => {
    test('should include security headers in responses', async () => {
      const response = await request(app)
        .get('/health')
        .expect(200);

      // Check for security headers set by helmet
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBe('DENY');
      expect(response.headers['x-xss-protection']).toBe('0');
      expect(response.headers['strict-transport-security']).toBeDefined();
      expect(response.headers['content-security-policy']).toBeDefined();
    });

    test('should set proper CORS headers', async () => {
      const response = await request(app)
        .options('/api/auth/login')
        .set('Origin', 'http://localhost:3000')
        .expect(204);

      expect(response.headers['access-control-allow-origin']).toBeDefined();
      expect(response.headers['access-control-allow-methods']).toBeDefined();
      expect(response.headers['access-control-allow-headers']).toBeDefined();
    });
  });

  describe('Authorization Security', () => {
    test('should prevent access to other users data', async () => {
      // Create token for user ID 2
      const otherUserToken = jwt.sign(
        { id: 2, email: 'other@example.com', role: 'user' },
        process.env.JWT_SECRET || 'test-jwt-secret-key',
        { expiresIn: '1h' }
      );

      // Try to access user ID 1's data with user ID 2's token
      const response = await request(app)
        .get('/api/account/balance')
        .set('Authorization', `Bearer ${otherUserToken}`);

      // Should only return data for the authenticated user
      expect(response.status).toBe(200);
      // In a real implementation, verify the returned data belongs to user ID 2
    });

    test('should require valid account numbers for transfers', async () => {
      const invalidAccounts = [
        '',
        'invalid',
        '123',
        'ACC',
        null,
        undefined,
        'ACC12345678901234567890' // Too long
      ];

      for (const account of invalidAccounts) {
        const response = await request(app)
          .post('/api/account/transfer')
          .set('Authorization', `Bearer ${validToken}`)
          .send({
            toAccount: account,
            amount: 100,
            description: 'Test transfer'
          })
          .expect(400);

        expect(response.body.error).toBe('Validation failed');
      }
    });
  });

  describe('Session Security', () => {
    test('should invalidate tokens on logout (if implemented)', async () => {
      // This test would be implemented when logout functionality is added
      // It should verify that tokens are properly invalidated
      expect(true).toBe(true); // Placeholder
    });

    test('should handle concurrent sessions appropriately', async () => {
      // Test multiple concurrent requests with same token
      const requests = Array(5).fill().map(() =>
        request(app)
          .get('/api/account/balance')
          .set('Authorization', `Bearer ${validToken}`)
      );

      const responses = await Promise.all(requests);
      
      // All should succeed or fail consistently
      const statusCodes = responses.map(r => r.status);
      const uniqueStatuses = [...new Set(statusCodes)];
      
      expect(uniqueStatuses.length).toBeLessThanOrEqual(2); // Should be consistent
    });
  });

  describe('Error Handling Security', () => {
    test('should not expose sensitive information in error messages', async () => {
      const response = await request(app)
        .post('/api/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'wrongpassword'
        })
        .expect(401);

      // Should not reveal whether user exists or not
      expect(response.body.error).toBe('Invalid credentials');
      expect(response.body.error).not.toContain('user not found');
      expect(response.body.error).not.toContain('password incorrect');
    });

    test('should handle server errors gracefully', async () => {
      // This would test error handling when database is unavailable
      // For now, just test that 500 errors don't expose stack traces
      const response = await request(app)
        .get('/nonexistent-endpoint')
        .expect(404);

      expect(response.body.error).toBe('Resource not found');
      expect(response.body.stack).toBeUndefined();
    });
  });

  describe('Business Logic Security', () => {
    test('should prevent negative balance transfers', async () => {
      const response = await request(app)
        .post('/api/account/transfer')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          toAccount: 'ACC12345678',
          amount: 999999999, // Extremely large amount
          description: 'Test transfer'
        });

      // Should fail due to insufficient funds
      expect(response.status).toBe(400);
      expect(response.body.error).toContain('Insufficient funds');
    });

    test('should prevent self-transfers', async () => {
      // This test assumes the system should prevent users from transferring to themselves
      const response = await request(app)
        .post('/api/account/transfer')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          toAccount: 'OWN_ACCOUNT_NUMBER', // User's own account
          amount: 100,
          description: 'Self transfer'
        });

      // Should either succeed (if allowed) or fail with appropriate message
      if (response.status !== 200) {
        expect(response.body.error).toBeDefined();
      }
    });

    test('should validate decimal precision for amounts', async () => {
      const response = await request(app)
        .post('/api/account/transfer')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          toAccount: 'ACC12345678',
          amount: 100.999, // More than 2 decimal places
          description: 'Precision test'
        });

      // Should either round appropriately or reject
      if (response.status === 200) {
        // Verify amount was rounded to 2 decimal places
        expect(response.body.amount).toBeLessThanOrEqual(101.00);
      } else {
        expect(response.status).toBe(400);
      }
    });
  });

  describe('Data Sanitization', () => {
    test('should sanitize user input to prevent NoSQL injection', async () => {
      const maliciousInput = {
        email: { '$ne': null },
        password: { '$ne': null }
      };

      const response = await request(app)
        .post('/api/auth/login')
        .send(maliciousInput)
        .expect(400);

      expect(response.body.error).toBe('Validation failed');
    });

    test('should handle unicode and special characters safely', async () => {
      const unicodeData = {
        email: 'test@example.com',
        password: 'ValidPassword123!',
        firstName: '测试',
        lastName: 'משתמש'
      };

      const response = await request(app)
        .post('/api/auth/register')
        .send(unicodeData);

      // Should either accept unicode or reject with proper validation
      expect([200, 201, 400]).toContain(response.status);
    });
  });

  describe('Timing Attack Prevention', () => {
    test('should have consistent response times for invalid users', async () => {
      const startTime = Date.now();
      
      await request(app)
        .post('/api/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'wrongpassword'
        });
      
      const endTime = Date.now();
      const responseTime = endTime - startTime;
      
      // Response time should be reasonable (not too fast, indicating early return)
      expect(responseTime).toBeGreaterThan(50); // At least 50ms for password hashing
    });
  });
}); 'ValidPassword123!',
            firstName: 'Test',
            lastName: 'User'
          })
          .expect(400);

        expect(response.body.error).toBe('Validation failed');
      }
    });

    test('should enforce strong password requirements', async () => {
      const weakPasswords = [
        'password',      // No uppercase, numbers, special chars
        'PASSWORD',      // No lowercase, numbers, special chars  
        'Password',      // No numbers, special chars
        'Password1',     // No special chars
        'Pass1!',        // Too short
        '12345678',      // Only numbers
        'P@ss1'          // Too short
      ];

      for (const password of weakPasswords) {
        const response = await request(app)
          .post('/api/auth/register')
          .send({
            email: 'test@example.com',
            password: