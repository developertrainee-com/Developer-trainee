// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  user: {
    type: String,
    required: true
  },
  domain: {
    type: String,
    required: true,
    index: true
  },
  territory: String,
  displayName: String,
  
  // NetSapiens tokens (ENCRYPTED, used by backend only)
  netsapiensToken: {
    access_token: String,      // Encrypted
    refresh_token: String,     // Encrypted
    expires_at: Date
  },
  
  lastLogin: {
    type: Date,
    default: Date.now
  },
  
  // Active refresh tokens (for session management)
  activeSessions: [{
    refreshToken: String,      // JWT refresh token (hashed)
    jti: String,              // Token ID for blacklisting
    deviceInfo: String,
    ipAddress: String,
    createdAt: {
      type: Date,
      default: Date.now
    },
    lastUsed: {
      type: Date,
      default: Date.now
    },
    expiresAt: Date
  }],
  
  // Legacy history (keeping for backward compatibility)
  callHistory: [{
    destination: String,
    callId: String,
    callerIdNumber: String,
    autoAnswerEnabled: String,
    timestamp: {
      type: Date,
      default: Date.now
    },
    status: String
  }],
  
  smsHistory: [{
    destination: String,
    fromNumber: String,
    message: String,
    messageSession: String,
    timestamp: {
      type: Date,
      default: Date.now
    }
  }]
}, {
  timestamps: true
});

// Indexes for performance
userSchema.index({ username: 1, domain: 1 });
userSchema.index({ 'activeSessions.jti': 1 });
userSchema.index({ 'activeSessions.expiresAt': 1 });
userSchema.index({ 'callHistory.timestamp': -1 });
userSchema.index({ 'smsHistory.timestamp': -1 });

// Limit histories
userSchema.pre('save', function(next) {
  if (this.callHistory && this.callHistory.length > 100) {
    this.callHistory = this.callHistory.slice(-100);
  }
  if (this.smsHistory && this.smsHistory.length > 50) {
    this.smsHistory = this.smsHistory.slice(-50);
  }
  
  // Remove expired sessions
  if (this.activeSessions && this.activeSessions.length > 0) {
    const now = new Date();
    this.activeSessions = this.activeSessions.filter(session => {
      return session.expiresAt > now;
    });
    
    // Limit to 5 active sessions per user
    if (this.activeSessions.length > 5) {
      this.activeSessions = this.activeSessions.slice(-5);
    }
  }
  
  next();
});

// Method to add active session
userSchema.methods.addSession = function(refreshToken, jti, deviceInfo, ipAddress, expiresAt) {
  if (!this.activeSessions) {
    this.activeSessions = [];
  }
  
  // Hash refresh token before storing
  const crypto = require('crypto');
  const hashedToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
  
  this.activeSessions.push({
    refreshToken: hashedToken,
    jti: jti,
    deviceInfo: deviceInfo || 'Unknown',
    ipAddress: ipAddress || 'Unknown',
    createdAt: new Date(),
    lastUsed: new Date(),
    expiresAt: expiresAt
  });
  
  return this.save();
};

// Method to remove session by jti
userSchema.methods.removeSession = function(jti) {
  if (!this.activeSessions) {
    return this.save();
  }
  
  this.activeSessions = this.activeSessions.filter(session => session.jti !== jti);
  return this.save();
};

// Method to remove all sessions (logout all devices)
userSchema.methods.removeAllSessions = function() {
  this.activeSessions = [];
  return this.save();
};

// Method to verify session exists
userSchema.methods.hasSession = function(refreshToken) {
  if (!this.activeSessions || this.activeSessions.length === 0) {
    return false;
  }
  
  const crypto = require('crypto');
  const hashedToken = crypto.createHash('sha256').update(refreshToken).digest('hex');
  
  return this.activeSessions.some(session => {
    return session.refreshToken === hashedToken && session.expiresAt > new Date();
  });
};

module.exports = mongoose.model('User', userSchema);