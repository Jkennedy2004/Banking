const mysql = require('mysql2/promise');

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'banking_user',
  password: process.env.DB_PASSWORD || 'secure_password',
  database: process.env.DB_NAME || 'banking_db',
  ssl: process.env.DB_SSL === 'true' ? {
    rejectUnauthorized: false
  } : false,
  connectionLimit: 10,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true
};

// Create connection pool
const pool = mysql.createPool(dbConfig);

/**
 * Execute SQL query with parameters
 * @param {string} query - SQL query
 * @param {Array} params - Query parameters
 * @returns {Promise} Query result
 */
async function executeQuery(query, params = []) {
  let connection;
  try {
    connection = await pool.getConnection();
    const [rows, fields] = await connection.execute(query, params);
    return rows;
  } catch (error) {
    console.error('Database query error:', error);
    throw error;
  } finally {
    if (connection) {
      connection.release();
    }
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
    WHERE email = ? AND deleted_at IS NULL
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
    VALUES (?, ?, ?, ?, ?, ?, NOW())
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
  return result.insertId;
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
    VALUES (?, ?, ?, ?, 'active', NOW())
  `;
  
  const params = [userId, accountNumber, accountType, initialBalance];
  const result = await executeQuery(query, params);
  return result.insertId;
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
    WHERE user_id = ? AND status = 'active' AND deleted_at IS NULL
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
    WHERE a.user_id = ? AND t.deleted_at IS NULL
    ORDER BY t.created_at DESC
    LIMIT ? OFFSET ?
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
  const connection = await pool.getConnection();
  
  try {
    await connection.beginTransaction();
    
    // Get sender account
    const [fromAccounts] = await connection.execute(
      'SELECT id, balance FROM accounts WHERE user_id = ? AND status = "active"',
      [fromUserId]
    );
    
    if (fromAccounts.length === 0) {
      throw new Error('Sender account not found');
    }
    
    const fromAccount = fromAccounts[0];
    
    // Check sufficient balance
    if (fromAccount.balance < amount) {
      throw new Error('Insufficient funds');
    }
    
    // Get recipient account
    const [toAccounts] = await connection.execute(
      'SELECT id, user_id FROM accounts WHERE account_number = ? AND status = "active"',
      [toAccountNumber]
    );
    
    if (toAccounts.length === 0) {
      throw new Error('Recipient account not found');
    }
    
    const toAccount = toAccounts[0];
    
    // Update sender balance
    const newFromBalance = fromAccount.balance - amount;
    await connection.execute(
      'UPDATE accounts SET balance = ?, updated_at = NOW() WHERE id = ?',
      [newFromBalance, fromAccount.id]
    );
    
    // Update recipient balance
    await connection.execute(
      'UPDATE accounts SET balance = balance + ?, updated_at = NOW() WHERE id = ?',
      [amount, toAccount.id]
    );
    
    // Create debit transaction
    const [debitResult] = await connection.execute(`
      INSERT INTO transactions 
      (from_account_id, to_account_id, type, amount, description, balance_after, 
       from_account_number, to_account_number, created_at)
      VALUES (?, ?, 'debit', ?, ?, ?, 
              (SELECT account_number FROM accounts WHERE id = ?),
              ?, NOW())
    `, [fromAccount.id, toAccount.id, amount, description, newFromBalance, fromAccount.id, toAccountNumber]);
    
    // Create credit transaction
    await connection.execute(`
      INSERT INTO transactions 
      (from_account_id, to_account_id, type, amount, description, balance_after,
       from_account_number, to_account_number, created_at)
      VALUES (?, ?, 'credit', ?, ?, 
              (SELECT balance FROM accounts WHERE id = ?),
              (SELECT account_number FROM accounts WHERE id = ?),
              ?, NOW())
    `, [fromAccount.id, toAccount.id, amount, description, toAccount.id, fromAccount.id, toAccountNumber]);
    
    await connection.commit();
    
    return {
      success: true,
      transactionId: debitResult.insertId
    };
    
  } catch (error) {
    await connection.rollback();
    console.error('Transfer error:', error);
    return {
      success: false,
      error: error.message
    };
  } finally {
    connection.release();
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
    VALUES (?, ?, false, NOW())
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
    VALUES (?, ?, true, NOW())
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
    WHERE email = ? AND success = false 
    AND created_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
  `;
  
  const result = await executeQuery(query, [email]);
  return result[0].count;
}

/**
 * Clear failed login attempts
 * @param {string} email - User email
 */
async function clearFailedLoginAttempts(email) {
  const query = `
    DELETE FROM login_attempts
    WHERE email = ? AND success = false
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
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      first_name VARCHAR(100) NOT NULL,
      last_name VARCHAR(100) NOT NULL,
      status ENUM('active', 'inactive', 'suspended') DEFAULT 'active',
      role ENUM('user', 'admin') DEFAULT 'user',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      deleted_at TIMESTAMP NULL
    )`,
    
    `CREATE TABLE IF NOT EXISTS accounts (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      account_number VARCHAR(20) UNIQUE NOT NULL,
      account_type ENUM('checking', 'savings') DEFAULT 'checking',
      balance DECIMAL(15,2) DEFAULT 0.00,
      status ENUM('active', 'inactive', 'closed') DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT