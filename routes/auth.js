// routes/auth.js
const express = require('express');
const router = express.Router();
const axios = require('axios');
const User = require('../models/User');
const auth = require('../middleware/auth');
const { generateAccessToken, generateRefreshToken, verifyToken, decodeToken, getTokenExpiry } = require('../utils/jwt');
const { blacklistToken } = require('../utils/tokenBlacklist');
const { encrypt, decrypt } = require('../utils/encryption');

// Test NetSapiens API connection
router.get('/test-connection', async (req, res) => {
  try {
    const response = await axios.get(`${process.env.NETSAPIENS_API_URL}/ping`, {
      timeout: 5000
    });
    
    res.json({
      success: true,
      message: 'NetSapiens API is reachable',
      apiUrl: process.env.NETSAPIENS_API_URL,
      apiVersion: response.data?.apiversion || 'Unknown'
    });
  } catch (error) {
    console.error('Connection test failed:', error.message);
    res.status(500).json({
      success: false,
      error: 'Failed to connect to NetSapiens API',
      apiUrl: process.env.NETSAPIENS_API_URL,
      details: error.message
    });
  }
});

// Login endpoint - UPDATED WITH JWT
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: 'Username and password are required'
      });
    }

    console.log('=== Login Request ===');
    console.log('Username:', username);
    console.log('IP:', req.ip);
    console.log('User-Agent:', req.headers['user-agent']);

    // Call NetSapiens OAuth2 token endpoint to validate credentials
    const tokenResponse = await axios.post(
      `${process.env.NETSAPIENS_API_URL}/tokens`,
      {
        grant_type: 'password',
        client_id: process.env.NETSAPIENS_CLIENT_ID,
        client_secret: process.env.NETSAPIENS_CLIENT_SECRET,
        username: username,
        password: password
      },
      {
        headers: {
          'Content-Type': 'application/json'
        },
        timeout: 10000
      }
    );

    console.log('✓ NetSapiens authentication successful');

    const tokenData = tokenResponse.data;

    // Calculate NetSapiens token expiration
    const netsapiensExpiresAt = new Date(Date.now() + (tokenData.expires_in * 1000));

    // Encrypt NetSapiens tokens before storing
    const encryptedAccessToken = encrypt(tokenData.access_token);
    const encryptedRefreshToken = encrypt(tokenData.refresh_token);

    // Create or update user in database
    let user = await User.findOne({ username: tokenData.username });

    if (user) {
      console.log('Existing user found, updating tokens');
      user.user = tokenData.user;
      user.domain = tokenData.domain;
      user.territory = tokenData.territory || '';
      user.displayName = tokenData.displayName || '';
      user.netsapiensToken = {
        access_token: encryptedAccessToken,
        refresh_token: encryptedRefreshToken,
        expires_at: netsapiensExpiresAt
      };
      user.lastLogin = new Date();
    } else {
      console.log('New user, creating account');
      user = new User({
        username: tokenData.username,
        user: tokenData.user,
        domain: tokenData.domain,
        territory: tokenData.territory || '',
        displayName: tokenData.displayName || '',
        netsapiensToken: {
          access_token: encryptedAccessToken,
          refresh_token: encryptedRefreshToken,
          expires_at: netsapiensExpiresAt
        },
        lastLogin: new Date()
      });
    }

    await user.save();

    // Generate YOUR JWT tokens
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Decode to get jti and expiry
    const refreshDecoded = decodeToken(refreshToken);
    const refreshExpiresAt = getTokenExpiry(refreshToken);

    // Save refresh token session
    await user.addSession(
      refreshToken,
      refreshDecoded.jti,
      req.headers['user-agent'],
      req.ip,
      refreshExpiresAt
    );

    console.log('✓ User logged in successfully:', user.username);
    console.log('✓ JWT tokens generated');
    console.log('Access token expires:', getTokenExpiry(accessToken)?.toISOString());
    console.log('Refresh token expires:', refreshExpiresAt?.toISOString());

    // Return YOUR JWT tokens to client (NOT NetSapiens tokens)
    res.json({
      success: true,
      accessToken: accessToken,
      refreshToken: refreshToken,
      expiresIn: process.env.JWT_ACCESS_EXPIRY || '30m',
      user: {
        username: user.username,
        user: user.user,
        domain: user.domain,
        territory: user.territory,
        displayName: user.displayName
      }
    });

  } catch (error) {
    console.error('=== Login Error ===');
    console.error('Error message:', error.message);
    console.error('Error response:', error.response?.data);
    
    if (error.response?.status === 401) {
      return res.status(401).json({
        error: 'Invalid username or password'
      });
    }

    res.status(error.response?.status || 500).json({
      error: 'Authentication failed',
      message: error.response?.data?.message || error.message
    });
  }
});

// Refresh token endpoint - NEW
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        error: 'Refresh token is required',
        needsReauth: true
      });
    }

    console.log('=== Token Refresh Request ===');

    // Verify refresh token
    const verification = verifyToken(refreshToken);

    if (!verification.valid) {
      console.error('Refresh token verification failed:', verification.error);
      return res.status(401).json({
        error: verification.expired ? 'Refresh token expired' : 'Invalid refresh token',
        needsReauth: true
      });
    }

    const decoded = verification.decoded;

    // Check token type
    if (decoded.type !== 'refresh') {
      console.error('Wrong token type:', decoded.type);
      return res.status(401).json({
        error: 'Invalid token type',
        needsReauth: true
      });
    }

    // Check if token is blacklisted
    const { isTokenBlacklisted } = require('../utils/tokenBlacklist');
    const isBlacklisted = await isTokenBlacklisted(decoded.jti);
    if (isBlacklisted) {
      console.error('Refresh token is blacklisted');
      return res.status(401).json({
        error: 'Token has been revoked',
        needsReauth: true
      });
    }

    // Fetch user
    const user = await User.findById(decoded.userId);

    if (!user) {
      console.error('User not found');
      return res.status(401).json({
        error: 'User not found',
        needsReauth: true
      });
    }

    // Verify session exists
    if (!user.hasSession(refreshToken)) {
      console.error('Session not found or expired');
      return res.status(401).json({
        error: 'Session not found',
        needsReauth: true
      });
    }

    // Generate new access token
    const newAccessToken = generateAccessToken(user);

    console.log('✓ New access token generated for:', user.username);
    console.log('New access token expires:', getTokenExpiry(newAccessToken)?.toISOString());

    // Optionally: Generate new refresh token (rotation)
    // For now, reuse the same refresh token
    
    res.json({
      success: true,
      accessToken: newAccessToken,
      expiresIn: process.env.JWT_ACCESS_EXPIRY || '30m'
    });

  } catch (error) {
    console.error('=== Token Refresh Error ===');
    console.error('Error:', error.message);
    
    res.status(500).json({
      error: 'Token refresh failed',
      message: error.message,
      needsReauth: false
    });
  }
});

// Get current user info - UPDATED
router.get('/me', auth, async (req, res) => {
  try {
    const user = req.user;

    res.json({
      success: true,
      user: {
        username: user.username,
        user: user.user,
        domain: user.domain,
        territory: user.territory,
        displayName: user.displayName,
        lastLogin: user.lastLogin,
        activeSessions: user.activeSessions?.length || 0
      }
    });

  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user info' });
  }
});

// Logout endpoint - UPDATED
router.post('/logout', auth, async (req, res) => {
  try {
    const user = req.user;
    const tokenPayload = req.tokenPayload;

    console.log('=== Logout Request ===');
    console.log('User:', user.username);
    console.log('Token JTI:', tokenPayload.jti);

    // Blacklist the access token
    const accessTokenExpiry = tokenPayload.exp - Math.floor(Date.now() / 1000);
    await blacklistToken(tokenPayload.jti, accessTokenExpiry);

    // Remove session from user (if refresh token provided)
    const { refreshToken } = req.body;
    if (refreshToken) {
      const refreshDecoded = decodeToken(refreshToken);
      if (refreshDecoded && refreshDecoded.jti) {
        await user.removeSession(refreshDecoded.jti);
        
        // Blacklist refresh token too
        const refreshExpiry = refreshDecoded.exp - Math.floor(Date.now() / 1000);
        await blacklistToken(refreshDecoded.jti, refreshExpiry);
        
        console.log('✓ Session removed and refresh token blacklisted');
      }
    }

    console.log('✓ User logged out successfully');

    res.json({ 
      success: true, 
      message: 'Logged out successfully' 
    });

  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// Logout from all devices - NEW
router.post('/logout-all', auth, async (req, res) => {
  try {
    const user = req.user;

    console.log('=== Logout All Devices ===');
    console.log('User:', user.username);

    // Blacklist all sessions
    if (user.activeSessions && user.activeSessions.length > 0) {
      for (const session of user.activeSessions) {
        const expirySeconds = Math.floor((session.expiresAt - new Date()) / 1000);
        if (expirySeconds > 0) {
          await blacklistToken(session.jti, expirySeconds);
        }
      }
    }

    // Remove all sessions
    await user.removeAllSessions();

    // Blacklist current access token
    const tokenPayload = req.tokenPayload;
    const accessTokenExpiry = tokenPayload.exp - Math.floor(Date.now() / 1000);
    await blacklistToken(tokenPayload.jti, accessTokenExpiry);

    console.log('✓ All sessions revoked');

    res.json({ 
      success: true, 
      message: 'Logged out from all devices successfully' 
    });

  } catch (error) {
    console.error('Logout all error:', error);
    res.status(500).json({ error: 'Logout all failed' });
  }
});

// Get active sessions - NEW
router.get('/sessions', auth, async (req, res) => {
  try {
    const user = req.user;

    const sessions = (user.activeSessions || []).map(session => ({
      deviceInfo: session.deviceInfo,
      ipAddress: session.ipAddress,
      createdAt: session.createdAt,
      lastUsed: session.lastUsed,
      expiresAt: session.expiresAt,
      isCurrent: session.jti === req.tokenPayload.jti
    }));

    res.json({
      success: true,
      sessions: sessions
    });

  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({ error: 'Failed to get sessions' });
  }
});

// Helper function to get NetSapiens token for backend use
const getNetSapiensToken = async (user) => {
  // Decrypt tokens
  const accessToken = decrypt(user.netsapiensToken.access_token);
  const refreshToken = decrypt(user.netsapiensToken.refresh_token);
  const expiresAt = user.netsapiensToken.expires_at;

  // Check if NetSapiens token is expired
  if (expiresAt && new Date() > expiresAt) {
    console.log('NetSapiens token expired, refreshing...');
    
    // Refresh NetSapiens token
    try {
      const tokenResponse = await axios.post(
        `${process.env.NETSAPIENS_API_URL}/tokens`,
        {
          grant_type: 'refresh_token',
          client_id: process.env.NETSAPIENS_CLIENT_ID,
          client_secret: process.env.NETSAPIENS_CLIENT_SECRET,
          refresh_token: refreshToken
        },
        {
          headers: {
            'Content-Type': 'application/json'
          },
          timeout: 10000
        }
      );

      const tokenData = tokenResponse.data;
      const newExpiresAt = new Date(Date.now() + (tokenData.expires_in * 1000));

      // Encrypt and update
      user.netsapiensToken.access_token = encrypt(tokenData.access_token);
      user.netsapiensToken.refresh_token = encrypt(tokenData.refresh_token || refreshToken);
      user.netsapiensToken.expires_at = newExpiresAt;
      await user.save();

      console.log('✓ NetSapiens token refreshed');

      return tokenData.access_token;
    } catch (error) {
      console.error('Failed to refresh NetSapiens token:', error.message);
      throw new Error('NetSapiens token refresh failed');
    }
  }

  return accessToken;
};

// Export helper for use in other routes
router.getNetSapiensToken = getNetSapiensToken;

module.exports = router;