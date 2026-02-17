// middleware/auth.js
const User = require('../models/User');
const { verifyToken } = require('../utils/jwt');
const { isTokenBlacklisted } = require('../utils/tokenBlacklist');

module.exports = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    console.log('=== Auth Middleware ===');
    console.log('Authorization header:', authHeader ? 'EXISTS' : 'MISSING');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.error('No Bearer token in header');
      return res.status(401).json({ 
        error: 'No token provided',
        needsReauth: true 
      });
    }

    // Extract JWT token
    const token = authHeader.substring(7);
    console.log('Token length:', token.length);

    // Verify JWT signature and expiration
    const verification = verifyToken(token);
    
    if (!verification.valid) {
      console.error('Token verification failed:', verification.error);
      
      if (verification.expired) {
        return res.status(401).json({ 
          error: 'Token expired',
          needsRefresh: true,
          needsReauth: false
        });
      }
      
      return res.status(401).json({ 
        error: 'Invalid token',
        needsReauth: true 
      });
    }

    const decoded = verification.decoded;
    console.log('Token decoded - User:', decoded.username, 'Type:', decoded.type);

    // Check if token type is access (not refresh)
    if (decoded.type !== 'access') {
      console.error('Wrong token type:', decoded.type);
      return res.status(401).json({ 
        error: 'Invalid token type',
        needsReauth: true 
      });
    }

    // Check if token is blacklisted (logged out)
    const isBlacklisted = await isTokenBlacklisted(decoded.jti);
    if (isBlacklisted) {
      console.error('Token is blacklisted (logged out)');
      return res.status(401).json({ 
        error: 'Token has been revoked',
        needsReauth: true 
      });
    }

    // Fetch user from database
    const user = await User.findById(decoded.userId);

    if (!user) {
      console.error('User not found for userId:', decoded.userId);
      return res.status(401).json({ 
        error: 'User not found',
        needsReauth: true 
      });
    }

    console.log('✓ User authenticated:', user.username);

    // Attach user to request
    req.user = user;
    req.tokenPayload = decoded; // Include decoded token for potential use
    
    next();

  } catch (error) {
    console.error('Auth middleware error:', error);
    return res.status(500).json({ 
      error: 'Authentication failed',
      message: error.message 
    });
  }
};