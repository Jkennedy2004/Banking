const { Pool } = require('pg');

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'banking_user',
  password: process.env.DB_PASSWORD || 'BankingSecure123!',
  database: process.env.DB_NAME || 'banking_db',
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
  max: 10, // maximum number of clients in the pool
  idleTimeoutMillis: 30000, // how long a client is allowed to remain idle before being closed
  connectionTimeoutMillis: 2000, // how long to wait when connecting a new client
};

// Create connection pool
const pool = new Pool(dbConfig);

// Handle pool errors
pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
  process.exit(-1);
});

/**
 * Execute SQL query with parameters
 * @param {string} query - SQL query
 * @param {Array} params - Query parameters
 * @returns {Promise} Query result
 */
async function executeQuery(query, params = []) {
  const client = await pool.connect();
  try {
    const result = await client.query(query, params);
    return result.rows;
  } catch (error) {
    console.error('Database query error:', error);
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Get user by email
 * @param {string} email - User email
 * @returns {Promise<Object|null>} User object or null
 */
async function getUserByEmail(email) {
  const query = `
    SELECT id, email, password_hash, first_name, last_name, status, role, created_at
    FROM users 
    WHERE email = $1 AND deleted_at IS NULL
  `;
  
  const users = await executeQuery(query, [email]);
  return users.length > 0 ? users[0] : null;
}

/**
 * Create new user
 * @param {Object} userData - User data
 * @returns {Promise<number>} User ID
 */
async function createUser(userData) {
  const query = `
    INSERT INTO users (email, password_hash, first_name, last_name, status, role, created_at)
    VALUES ($1, $2, $3, $4, $5, $6, NOW())
    RETURNING id
  `;
  
  const params = [
    userData.email,
    userData.password_hash,
    userData.first_name,
    userData.last_name,
    userData.status,
    userData.role
  ];
  
  const result = await executeQuery(query, params);
  return result[0].id;
}

/**
 * Create new account for user
 * @param {number} userId - User ID
 * @param {string} accountType - Account type (checking, savings)
 * @param {number} initialBalance - Initial balance
 * @returns {Promise<number>} Account ID
 */
async function createAccount(userId, accountType, initialBalance = 0) {
  const accountNumber = generateAccountNumber();
  
  const query = `
    INSERT INTO accounts (user_id, account_number, account_type, balance, status, created_at)
    VALUES ($1, $2, $3, $4, 'active', NOW())
    RETURNING id
  `;
  
  const params = [userId, accountNumber, accountType, initialBalance];
  const result = await executeQuery(query, params);
  return result[0].id;
}

/**
 * Get account balance for user
 * @param {number} userId - User ID
 * @returns {Promise<number>} Account balance
 */
async function getAccountBalance(userId) {
  const query = `
    SELECT balance 
    FROM accounts 
    WHERE user_id = $1 AND status = 'active' AND deleted_at IS NULL
    ORDER BY created_at ASC
    LIMIT 1
  `;
  
  const accounts = await executeQuery(query, [userId]);
  return accounts.length > 0 ? parseFloat(accounts[0].balance) : 0;
}

/**
 * Get user transactions
 * @param {number} userId - User ID
 * @param {number} limit - Number of transactions to return
 * @param {number} offset - Offset for pagination
 * @returns {Promise<Array>} Array of transactions
 */
async function getTransactions(userId, limit = 10, offset = 0) {
  const query = `
    SELECT t.id, t.type, t.amount, t.description, t.balance_after, t.created_at,
           t.to_account_number, t.from_account_number
    FROM transactions t
    JOIN accounts a ON (t.from_account_id = a.id OR t.to_account_id = a.id)
    WHERE a.user_id = $1 AND t.deleted_at IS NULL
    ORDER BY t.created_at DESC
    LIMIT $2 OFFSET $3
  `;
  
  return await executeQuery(query, [userId, limit, offset]);
}

/**
 * Transfer funds between accounts
 * @param {number} fromUserId - Sender user ID
 * @param {string} toAccountNumber - Recipient account number
 * @param {number} amount - Transfer amount
 * @param {string} description - Transfer description
 * @returns {Promise<Object>} Transfer result
 */
async function transferFunds(fromUserId, toAccountNumber, amount, description = '') {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Get sender account
    const fromAccountQuery = 'SELECT id, balance FROM accounts WHERE user_id = $1 AND status = $2';
    const fromAccounts = await client.query(fromAccountQuery, [fromUserId, 'active']);
    
    if (fromAccounts.rows.length === 0) {
      throw new Error('Sender account not found');
    }
    
    const fromAccount = fromAccounts.rows[0];
    
    // Check sufficient balance
    if (parseFloat(fromAccount.balance) < amount) {
      throw new Error('Insufficient funds');
    }
    
    // Get recipient account
    const toAccountQuery = 'SELECT id, user_id FROM accounts WHERE account_number = $1 AND status = $2';
    const toAccounts = await client.query(toAccountQuery, [toAccountNumber, 'active']);
    
    if (toAccounts.rows.length === 0) {
      throw new Error('Recipient account not found');
    }
    
    const toAccount = toAccounts.rows[0];
    
    // Update sender balance
    const newFromBalance = parseFloat(fromAccount.balance) - amount;
    await client.query(
      'UPDATE accounts SET balance = $1, updated_at = NOW() WHERE id = $2',
      [newFromBalance, fromAccount.id]
    );
    
    // Update recipient balance
    await client.query(
      'UPDATE accounts SET balance = balance + $1, updated_at = NOW() WHERE id = $2',
      [amount, toAccount.id]
    );
    
    // Create debit transaction
    const debitQuery = `
      INSERT INTO transactions 
      (from_account_id, to_account_id, type, amount, description, balance_after, 
       from_account_number, to_account_number, created_at)
      VALUES ($1, $2, 'debit', $3, $4, $5, 
              (SELECT account_number FROM accounts WHERE id = $6),
              $7, NOW())
      RETURNING id
    `;
    const debitResult = await client.query(debitQuery, [
      fromAccount.id, toAccount.id, amount, description, newFromBalance, fromAccount.id, toAccountNumber
    ]);
    
    // Create credit transaction
    const creditQuery = `
      INSERT INTO transactions 
      (from_account_id, to_account_id, type, amount, description, balance_after,
       from_account_number, to_account_number, created_at)
      VALUES ($1, $2, 'credit', $3, $4, 
              (SELECT balance FROM accounts WHERE id = $5),
              (SELECT account_number FROM accounts WHERE id = $6),
              $7, NOW())
    `;
    await client.query(creditQuery, [
      fromAccount.id, toAccount.id, amount, description, toAccount.id, fromAccount.id, toAccountNumber
    ]);
    
    await client.query('COMMIT');
    
    return {
      success: true,
      transactionId: debitResult.rows[0].id
    };
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Transfer error:', error);
    return {
      success: false,
      error: error.message
    };
  } finally {
    client.release();
  }
}

/**
 * Log failed login attempt
 * @param {string} email - User email
 * @param {string} ipAddress - Client IP address
 */
async function logFailedLogin(email, ipAddress) {
  const query = `
    INSERT INTO login_attempts (email, ip_address, success, created_at)
    VALUES ($1, $2, false, NOW())
  `;
  
  await executeQuery(query, [email, ipAddress]);
}

/**
 * Log successful login
 * @param {number} userId - User ID
 * @param {string} ipAddress - Client IP address
 */
async function logSuccessfulLogin(userId, ipAddress) {
  const query = `
    INSERT INTO login_attempts (user_id, ip_address, success, created_at)
    VALUES ($1, $2, true, NOW())
  `;
  
  await executeQuery(query, [userId, ipAddress]);
}

/**
 * Get failed login attempts count
 * @param {string} email - User email
 * @returns {Promise<number>} Failed attempts count
 */
async function getFailedLoginAttempts(email) {
  const query = `
    SELECT COUNT(*) as count
    FROM login_attempts
    WHERE email = $1 AND success = false 
    AND created_at > NOW() - INTERVAL '15 minutes'
  `;
  
  const result = await executeQuery(query, [email]);
  return parseInt(result[0].count);
}

/**
 * Clear failed login attempts
 * @param {string} email - User email
 */
async function clearFailedLoginAttempts(email) {
  const query = `
    DELETE FROM login_attempts
    WHERE email = $1 AND success = false
  `;
  
  await executeQuery(query, [email]);
}

/**
 * Generate unique account number
 * @returns {string} Account number
 */
function generateAccountNumber() {
  const timestamp = Date.now().toString();
  const random = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
  return `ACC${timestamp.slice(-8)}${random}`;
}

/**
 * Initialize database tables
 */
async function initializeDatabase() {
  const tables = [
    `CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      first_name VARCHAR(100) NOT NULL,
      last_name VARCHAR(100) NOT NULL,
      status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
      role VARCHAR(20) DEFAULT 'user' CHECK (role IN ('user', 'admin')),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      deleted_at TIMESTAMP NULL
    )`,
    
    `CREATE TABLE IF NOT EXISTS accounts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      account_number VARCHAR(20) UNIQUE NOT NULL,
      account_type VARCHAR(20) DEFAULT 'checking' CHECK (account_type IN ('checking', 'savings')),
      balance DECIMAL(15,2) DEFAULT 0.00,
      status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'closed')),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      deleted_at TIMESTAMP NULL
    )`,
    
    `CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      from_account_id INTEGER REFERENCES accounts(id),
      to_account_id INTEGER REFERENCES accounts(id),
      type VARCHAR(20) NOT NULL CHECK (type IN ('debit', 'credit', 'deposit', 'withdrawal')),
      amount DECIMAL(15,2) NOT NULL,
      description VARCHAR(255),
      balance_after DECIMAL(15,2),
      from_account_number VARCHAR(20),
      to_account_number VARCHAR(20),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      deleted_at TIMESTAMP NULL
    )`,
    
    `CREATE TABLE IF NOT EXISTS login_attempts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      email VARCHAR(255),
      ip_address INET,
      success BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`
  ];

  for (const table of tables) {
    await executeQuery(table);
  }
  
  console.log('Database tables initialized successfully');
}

// Test database connection
async function testConnection() {
  try {
    const client = await pool.connect();
    console.log('Database connected successfully');
    client.release();
    return true;
  } catch (error) {
    console.error('Database connection failed:', error);
    return false;
  }
}

module.exports = {
  executeQuery,
  getUserByEmail,
  createUser,
  createAccount,
  getAccountBalance,
  getTransactions,
  transferFunds,
  logFailedLogin,
  logSuccessfulLogin,
  getFailedLoginAttempts,
  clearFailedLoginAttempts,
  generateAccountNumber,
  initializeDatabase,
  testConnection,
  pool
};