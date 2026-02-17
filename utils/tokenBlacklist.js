// utils/tokenBlacklist.js
const NodeCache = require('node-cache');

// In-memory blacklist (for development or single-server setup)
// In production, use Redis for distributed blacklist
const blacklistCache = new NodeCache({ stdTTL: 3600, checkperiod: 600 });

// Try to use Redis if available
let redisClient = null;
try {
  if (process.env.REDIS_URL) {
    const redis = require('redis');
    redisClient = redis.createClient({
      url: process.env.REDIS_URL
    });
    
    redisClient.connect().then(() => {
      console.log('✅ Redis connected for token blacklist');
    }).catch(err => {
      console.warn('⚠️ Redis connection failed, using in-memory blacklist:', err.message);
      redisClient = null;
    });
  }
} catch (error) {
  console.warn('⚠️ Redis not available, using in-memory blacklist');
}

// Add token to blacklist
const blacklistToken = async (jti, expirySeconds = 3600) => {
  try {
    if (redisClient && redisClient.isOpen) {
      // Use Redis
      await redisClient.setEx(`blacklist:${jti}`, expirySeconds, 'true');
      console.log('Token blacklisted in Redis:', jti.substring(0, 8) + '...');
    } else {
      // Use in-memory cache
      blacklistCache.set(jti, true, expirySeconds);
      console.log('Token blacklisted in memory:', jti.substring(0, 8) + '...');
    }
    return true;
  } catch (error) {
    console.error('Failed to blacklist token:', error);
    // Fallback to memory
    blacklistCache.set(jti, true, expirySeconds);
    return true;
  }
};

// Check if token is blacklisted
const isTokenBlacklisted = async (jti) => {
  try {
    if (redisClient && redisClient.isOpen) {
      // Check Redis
      const result = await redisClient.get(`blacklist:${jti}`);
      return result === 'true';
    } else {
      // Check in-memory cache
      return blacklistCache.get(jti) === true;
    }
  } catch (error) {
    console.error('Failed to check blacklist:', error);
    // Fallback to memory
    return blacklistCache.get(jti) === true;
  }
};

// Clear all blacklisted tokens (for testing)
const clearBlacklist = async () => {
  try {
    if (redisClient && redisClient.isOpen) {
      const keys = await redisClient.keys('blacklist:*');
      if (keys.length > 0) {
        await redisClient.del(keys);
      }
    }
    blacklistCache.flushAll();
    console.log('✓ Blacklist cleared');
  } catch (error) {
    console.error('Failed to clear blacklist:', error);
  }
};

module.exports = {
  blacklistToken,
  isTokenBlacklisted,
  clearBlacklist
};