const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const login = require('./login');
const database = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login attempts per windowMs
  skipSuccessfulRequests: true,
  message: {
    error: 'Too many login attempts, please try again later.'
  }
});

app.use(limiter);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'banking-app'
  });
});

// Authentication endpoints
app.post('/api/auth/login', 
  loginLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation failed',
          details: errors.array()
        });
      }

      const { email, password } = req.body;
      const result = await login.authenticate(email, password);
      
      if (result.success) {
        res.status(200).json({
          message: 'Login successful',
          token: result.token,
          user: result.user
        });
      } else {
        res.status(401).json({
          error: 'Invalid credentials'
        });
      }
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        error: 'Internal server error'
      });
    }
  }
);

app.post('/api/auth/register',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/),
    body('firstName').isLength({ min: 2 }).trim().escape(),
    body('lastName').isLength({ min: 2 }).trim().escape()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation failed',
          details: errors.array()
        });
      }

      const { email, password, firstName, lastName } = req.body;
      const result = await login.register(email, password, firstName, lastName);
      
      if (result.success) {
        res.status(201).json({
          message: 'User registered successfully',
          userId: result.userId
        });
      } else {
        res.status(400).json({
          error: result.error
        });
      }
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({
        error: 'Internal server error'
      });
    }
  }
);

// Protected routes middleware
app.use('/api/account', login.verifyToken);

// Account endpoints
app.get('/api/account/balance', async (req, res) => {
  try {
    const userId = req.user.id;
    const balance = await database.getAccountBalance(userId);
    
    res.status(200).json({
      balance: balance,
      currency: 'USD'
    });
  } catch (error) {
    console.error('Balance error:', error);
    res.status(500).json({
      error: 'Unable to retrieve balance'
    });
  }
});

app.get('/api/account/transactions', async (req, res) => {
  try {
    const userId = req.user.id;
    const { limit = 10, offset = 0 } = req.query;
    
    const transactions = await database.getTransactions(userId, parseInt(limit), parseInt(offset));
    
    res.status(200).json({
      transactions: transactions,
      count: transactions.length
    });
  } catch (error) {
    console.error('Transactions error:', error);
    res.status(500).json({
      error: 'Unable to retrieve transactions'
    });
  }
});

app.post('/api/account/transfer',
  [
    body('toAccount').isLength({ min: 8 }).isAlphanumeric(),
    body('amount').isFloat({ min: 0.01 }),
    body('description').optional().isLength({ max: 255 }).trim().escape()
  ],
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: 'Validation failed',
          details: errors.array()
        });
      }

      const userId = req.user.id;
      const { toAccount, amount, description } = req.body;
      
      const result = await database.transferFunds(userId, toAccount, amount, description);
      
      if (result.success) {
        res.status(200).json({
          message: 'Transfer completed successfully',
          transactionId: result.transactionId
        });
      } else {
        res.status(400).json({
          error: result.error
        });
      }
    } catch (error) {
      console.error('Transfer error:', error);
      res.status(500).json({
        error: 'Transfer failed'
      });
    }
  }
);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Resource not found'
  });
});

// Start server
const server = app.listen(PORT, () => {
  console.log(`Banking app running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Process terminated');
    process.exit(0);
  });
});

module.exports = app;