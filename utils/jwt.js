// utils/jwt.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-this-in-production';
const JWT_ACCESS_EXPIRY = process.env.JWT_ACCESS_EXPIRY || '30m';
const JWT_REFRESH_EXPIRY = process.env.JWT_REFRESH_EXPIRY || '7d';

// Generate unique token ID
const generateTokenId = () => {
  return crypto.randomBytes(16).toString('hex');
};

// Generate Access Token (short-lived)
const generateAccessToken = (user) => {
  const payload = {
    userId: user._id.toString(),
    username: user.username,
    domain: user.domain,
    type: 'access',
    jti: generateTokenId()
  };

  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_ACCESS_EXPIRY,
    issuer: 'netsapiens-backend',
    audience: 'netsapiens-extension'
  });
};

// Generate Refresh Token (long-lived)
const generateRefreshToken = (user) => {
  const payload = {
    userId: user._id.toString(),
    username: user.username,
    type: 'refresh',
    jti: generateTokenId()
  };

  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_REFRESH_EXPIRY,
    issuer: 'netsapiens-backend',
    audience: 'netsapiens-extension'
  });
};

// Verify Token
const verifyToken = (token) => {
  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: 'netsapiens-backend',
      audience: 'netsapiens-extension'
    });
    return { valid: true, decoded };
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return { valid: false, expired: true, error: 'Token expired' };
    }
    if (error.name === 'JsonWebTokenError') {
      return { valid: false, expired: false, error: 'Invalid token' };
    }
    return { valid: false, expired: false, error: error.message };
  }
};

// Decode token without verification (for expired token inspection)
const decodeToken = (token) => {
  try {
    return jwt.decode(token);
  } catch (error) {
    return null;
  }
};

// Get token expiry time
const getTokenExpiry = (token) => {
  const decoded = decodeToken(token);
  if (decoded && decoded.exp) {
    return new Date(decoded.exp * 1000);
  }
  return null;
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyToken,
  decodeToken,
  getTokenExpiry,
  generateTokenId
};