const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const database = require('./database');

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';
const SALT_ROUNDS = 12;

/**
 * Authenticate user with email and password
 * @param {string} email - User email
 * @param {string} password - User password
 * @returns {Object} Authentication result
 */
async function authenticate(email, password) {
  try {
    // Input validation
    if (!email || !password) {
      return {
        success: false,
        error: 'Email and password are required'
      };
    }

    // Get user from database
    const user = await database.getUserByEmail(email);
    
    if (!user) {
      // Use same timing as password check to prevent timing attacks
      await bcrypt.compare(password, '$2a$12$dummy.hash.to.prevent.timing.attacks');
      return {
        success: false,
        error: 'Invalid credentials'
      };
    }

    // Check if account is active
    if (user.status !== 'active') {
      return {
        success: false,
        error: 'Account is not active'
      };
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    
    if (!isPasswordValid) {
      // Log failed login attempt
      await database.logFailedLogin(email, getClientIP());
      return {
        success: false,
        error: 'Invalid credentials'
      };
    }

    // Check for too many failed attempts
    const failedAttempts = await database.getFailedLoginAttempts(email);
    if (failedAttempts >= 5) {
      return {
        success: false,
        error: 'Account temporarily locked due to too many failed attempts'
      };
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      {
        expiresIn: JWT_EXPIRES_IN,
        issuer: 'banking-app',
        audience: 'banking-users'
      }
    );

    // Clear failed login attempts
    await database.clearFailedLoginAttempts(email);
    
    // Log successful login
    await database.logSuccessfulLogin(user.id, getClientIP());

    return {
      success: true,
      token: token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role
      }
    };

  } catch (error) {
    console.error('Authentication error:', error);
    return {
      success: false,
      error: 'Authentication failed'
    };
  }
}

/**
 * Register new user
 * @param {string} email - User email
 * @param {string} password - User password
 * @param {string} firstName - User first name
 * @param {string} lastName - User last name
 * @returns {Object} Registration result
 */
async function register(email, password, firstName, lastName) {
  try {
    // Check if user already exists
    const existingUser = await database.getUserByEmail(email);
    if (existingUser) {
      return {
        success: false,
        error: 'User already exists with this email'
      };
    }

    // Validate password strength
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return {
        success: false,
        error: passwordValidation.message
      };
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    // Create user
    const userId = await database.createUser({
      email: email.toLowerCase(),
      password_hash: passwordHash,
      first_name: firstName,
      last_name: lastName,
      status: 'active',
      role: 'user'
    });

    // Create initial account
    await database.createAccount(userId, 'checking', 0.00);

    return {
      success: true,
      userId: userId
    };

  } catch (error) {
    console.error('Registration error:', error);
    return {
      success: false,
      error: 'Registration failed'
    };
  }
}

/**
 * Middleware to verify JWT token
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Access token required'
      });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    jwt.verify(token, JWT_SECRET, {
      issuer: 'banking-app',
      audience: 'banking-users'
    }, (err, decoded) => {
      if (err) {
        if (err.name === 'TokenExpiredError') {
          return res.status(401).json({
            error: 'Token has expired'
          });
        } else if (err.name === 'JsonWebTokenError') {
          return res.status(401).json({
            error: 'Invalid token'
          });
        } else {
          return res.status(401).json({
            error: 'Token verification failed'
          });
        }
      }

      // Add user info to request
      req.user = decoded;
      next();
    });

  } catch (error) {
    console.error('Token verification error:', error);
    return res.status(500).json({
      error: 'Authentication verification failed'
    });
  }
}

/**
 * Validate password strength
 * @param {string} password - Password to validate
 * @returns {Object} Validation result
 */
function validatePassword(password) {
  if (password.length < 8) {
    return {
      valid: false,
      message: 'Password must be at least 8 characters long'
    };
  }

  if (!/(?=.*[a-z])/.test(password)) {
    return {
      valid: false,
      message: 'Password must contain at least one lowercase letter'
    };
  }

  if (!/(?=.*[A-Z])/.test(password)) {
    return {
      valid: false,
      message: 'Password must contain at least one uppercase letter'
    };
  }

  if (!/(?=.*\d)/.test(password)) {
    return {
      valid: false,
      message: 'Password must contain at least one number'
    };
  }

  if (!/(?=.*[@$!%*?&])/.test(password)) {
    return {
      valid: false,
      message: 'Password must contain at least one special character (@$!%*?&)'
    };
  }

  return {
    valid: true,
    message: 'Password is valid'
  };
}

/**
 * Get client IP address (placeholder for real implementation)
 * @returns {string} Client IP
 */
function getClientIP() {
  // In a real app, this would extract IP from request
  return '127.0.0.1';
}

/**
 * Generate secure random token
 * @param {number} length - Token length
 * @returns {string} Random token
 */
function generateSecureToken(length = 32) {
  const crypto = require('crypto');
  return crypto.randomBytes(length).toString('hex');
}

module.exports = {
  authenticate,
  register,
  verifyToken,
  validatePassword,
  generateSecureToken
};