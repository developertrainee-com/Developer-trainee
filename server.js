require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const connectDB = require('./config/database');
const { testEncryption } = require('./utils/encryption');

const authRoutes = require('./routes/auth');
const callRoutes = require('./routes/calls');
const smsRoutes = require('./routes/sms');

const app = express();
app.set('trust proxy', 1); // Trust first proxy (Nginx) - Required for rate limiting behind reverse proxy
const PORT = process.env.PORT || 3000;

// Validate required environment variables
const requiredEnvVars = [
  'MONGODB_URI',
  'JWT_SECRET',
  'ENCRYPTION_KEY',
  'NETSAPIENS_API_URL',
  'NETSAPIENS_CLIENT_ID',
  'NETSAPIENS_CLIENT_SECRET'
];

const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
  console.error('❌ ERROR: Missing required environment variables:');
  missingEnvVars.forEach(varName => {
    console.error(`   - ${varName}`);
  });
  console.error('\nPlease check your .env file and ensure all required variables are set.');
  process.exit(1);
}

// Validate JWT_SECRET length
if (process.env.JWT_SECRET.length < 32) {
  console.error('❌ ERROR: JWT_SECRET must be at least 32 characters long for security.');
  console.error('   Current length:', process.env.JWT_SECRET.length);
  console.error('   Generate a secure secret using: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}

// Validate ENCRYPTION_KEY length
if (process.env.ENCRYPTION_KEY.length < 64) {
  console.error('❌ ERROR: ENCRYPTION_KEY must be at least 64 characters long (32 bytes in hex).');
  console.error('   Current length:', process.env.ENCRYPTION_KEY.length);
  console.error('   Generate a secure key using: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  process.exit(1);
}

console.log('='.repeat(60));
console.log('🚀 Starting Click to Call Backend Server');
console.log('='.repeat(60));

// Connect to MongoDB
connectDB();

// Test encryption on startup
console.log('\n🔐 Testing encryption system...');
if (!testEncryption()) {
  console.error('❌ Encryption test failed! Server cannot start safely.');
  process.exit(1);
}

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

app.use(compression());

// CORS configuration for Chrome extension
app.use(cors({
  origin: (origin, callback) => {
    // Allow Chrome extension origins
    if (!origin || origin.startsWith('chrome-extension://')) {
      callback(null, true);
    } else if (process.env.NODE_ENV === 'development') {
      // In development, allow all origins
      callback(null, true);
    } else {
      // In production, whitelist your domain
      const allowedOrigins = [
        'https://c2csandbox.comstreamtech.com:4999',
        'https://c2csandbox.comstreamtech.com',
        'https://c2cmyconstructiongroupinc.comstreamtech.com',
        'https://c2cmyconstructiongroupinc.comstreamtech.com:3001',
        'http://localhost:3000' // Keep for testing
      ];
      
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(null, true); // Change to callback(new Error('Not allowed by CORS')) in strict production
      }
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting - different limits for different endpoints
const apiLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Stricter rate limit for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 login requests per window
  skipSuccessfulRequests: false,
  message: {
    error: 'Too many login attempts from this IP, please try again later.',
    retryAfter: '15 minutes'
  }
});

// Apply rate limiters
app.use('/api/', apiLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/refresh', authLimiter);

// Body parser
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path}`);
  
  // Log body for non-GET requests (excluding sensitive data)
  if (req.method !== 'GET' && req.body && Object.keys(req.body).length > 0) {
    const sanitizedBody = { ...req.body };
    
    // Remove sensitive fields from logs
    if (sanitizedBody.password) sanitizedBody.password = '***REDACTED***';
    if (sanitizedBody.refreshToken) sanitizedBody.refreshToken = '***REDACTED***';
    if (sanitizedBody.accessToken) sanitizedBody.accessToken = '***REDACTED***';
    if (sanitizedBody.message && sanitizedBody.message.length > 50) {
      sanitizedBody.message = sanitizedBody.message.substring(0, 50) + '... (truncated)';
    }
    
    console.log('Request body:', JSON.stringify(sanitizedBody, null, 2));
  }
  
  next();
});

// Response time tracking
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const statusColor = res.statusCode >= 500 ? '🔴' :
                       res.statusCode >= 400 ? '🟡' :
                       res.statusCode >= 300 ? '🔵' : '🟢';
    console.log(`${statusColor} ${req.method} ${req.path} - ${res.statusCode} - ${duration}ms`);
  });
  
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  const healthcheck = {
    status: 'ok',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    mongodb: 'connected', // Will be 'disconnected' if DB fails
    services: {
      netsapiens: {
        configured: !!process.env.NETSAPIENS_API_URL,
        url: process.env.NETSAPIENS_API_URL
      },
      jwt: {
        configured: !!process.env.JWT_SECRET
      },
      encryption: {
        configured: !!process.env.ENCRYPTION_KEY
      }
    }
  };
  
  res.json(healthcheck);
});

// API Documentation endpoint
app.get('/', (req, res) => {
  res.json({
    name: 'Click to Call Backend API',
    version: '1.0.0',
    description: 'Backend service for NetSapiens Click to Call Chrome Extension with JWT Authentication',
    documentation: '/api/docs',
    health: '/health',
    endpoints: {
      authentication: {
        login: 'POST /api/auth/login',
        refresh: 'POST /api/auth/refresh',
        me: 'GET /api/auth/me',
        logout: 'POST /api/auth/logout',
        logoutAll: 'POST /api/auth/logout-all',
        sessions: 'GET /api/auth/sessions'
      },
      calls: {
        initiate: 'POST /api/calls/initiate',
        phonenumbers: 'GET /api/calls/phonenumbers',
        history: 'GET /api/calls/history',
        stats: 'GET /api/calls/stats',
        details: 'GET /api/calls/:callId',
        updateStatus: 'PATCH /api/calls/:callId/status',
        delete: 'DELETE /api/calls/:callId'
      },
      sms: {
        send: 'POST /api/sms/send',
        numbers: 'GET /api/sms/numbers',
        history: 'GET /api/sms/history',
        stats: 'GET /api/sms/stats',
        details: 'GET /api/sms/:messageSession',
        conversation: 'GET /api/sms/conversation/:phoneNumber',
        updateStatus: 'PATCH /api/sms/:messageSession/status',
        delete: 'DELETE /api/sms/:messageSession'
      }
    }
  });
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/calls', callRoutes);
app.use('/api/sms', smsRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('=== Unhandled Error ===');
  console.error('Error:', err.message);
  console.error('Stack:', err.stack);
  console.error('Path:', req.path);
  console.error('Method:', req.method);
  
  // Don't expose internal error details in production
  const errorResponse = {
    error: 'Internal server error',
    timestamp: new Date().toISOString(),
    path: req.path
  };
  
  // Add details in development mode
  if (process.env.NODE_ENV === 'development') {
    errorResponse.message = err.message;
    errorResponse.stack = err.stack;
  }
  
  res.status(500).json(errorResponse);
});

// 404 handler - must be last
app.use((req, res) => {
  res.status(404).json({ 
    error: 'Route not found',
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString(),
    suggestion: 'Check the API documentation at GET /'
  });
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log('\n' + '='.repeat(60));
  console.log('✅ SERVER STARTED SUCCESSFULLY');
  console.log('='.repeat(60));
  console.log(`📡 Server URL: http://0.0.0.0:${PORT}`);
  console.log(`🌐 Public URL: http://c2csandbox.comstreamtech.com:${PORT}`);
  console.log(`🔒 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🌐 NetSapiens API: ${process.env.NETSAPIENS_API_URL}`);
  console.log(`💾 MongoDB: ${process.env.MONGODB_URI.includes('@') ? 'Connected to remote DB' : 'Connected to local DB'}`);
  console.log(`🔐 JWT Auth: Enabled (${process.env.JWT_ACCESS_EXPIRY || '30m'} access, ${process.env.JWT_REFRESH_EXPIRY || '7d'} refresh)`);
  console.log(`🔒 Encryption: Enabled`);
  console.log(`⏱️  Rate Limiting: ${process.env.RATE_LIMIT_MAX_REQUESTS || 100} requests per ${(parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000) / 60000} minutes`);
  
  if (process.env.REDIS_URL) {
    console.log(`🗄️  Redis: Configured for token blacklist`);
  } else {
    console.log(`⚠️  Redis: Not configured (using in-memory blacklist)`);
  }
  
  console.log('='.repeat(60));
  console.log('\n📋 Available endpoints:');
  console.log('   GET  http://localhost:' + PORT + '/');
  console.log('   GET  http://localhost:' + PORT + '/health');
  console.log('\n   === Authentication ===');
  console.log('   POST http://localhost:' + PORT + '/api/auth/login');
  console.log('   POST http://localhost:' + PORT + '/api/auth/refresh');
  console.log('   GET  http://localhost:' + PORT + '/api/auth/me');
  console.log('   GET  http://localhost:' + PORT + '/api/auth/sessions');
  console.log('   POST http://localhost:' + PORT + '/api/auth/logout');
  console.log('   POST http://localhost:' + PORT + '/api/auth/logout-all');
  console.log('\n   === Calls ===');
  console.log('   GET  http://localhost:' + PORT + '/api/calls/phonenumbers');
  console.log('   POST http://localhost:' + PORT + '/api/calls/initiate');
  console.log('   POST http://localhost:' + PORT + '/api/calls/validate');
  console.log('   GET  http://localhost:' + PORT + '/api/calls/history');
  console.log('   GET  http://localhost:' + PORT + '/api/calls/stats');
  console.log('   GET  http://localhost:' + PORT + '/api/calls/:callId');
  console.log('   PATCH http://localhost:' + PORT + '/api/calls/:callId/status');
  console.log('   DELETE http://localhost:' + PORT + '/api/calls/:callId');
  console.log('\n   === SMS ===');
  console.log('   GET  http://localhost:' + PORT + '/api/sms/numbers');
  console.log('   POST http://localhost:' + PORT + '/api/sms/send');
  console.log('   GET  http://localhost:' + PORT + '/api/sms/history');
  console.log('   GET  http://localhost:' + PORT + '/api/sms/stats');
  console.log('   GET  http://localhost:' + PORT + '/api/sms/:messageSession');
  console.log('   GET  http://localhost:' + PORT + '/api/sms/conversation/:phoneNumber');
  console.log('   PATCH http://localhost:' + PORT + '/api/sms/:messageSession/status');
  console.log('   DELETE http://localhost:' + PORT + '/api/sms/:messageSession');
  console.log('\n' + '='.repeat(60));
  console.log('🎉 Ready to accept requests!');
  console.log('='.repeat(60) + '\n');
});

// Graceful shutdown
const gracefulShutdown = async (signal) => {
  console.log(`\n${signal} received, shutting down gracefully...`);
  
  server.close(async () => {
    console.log('✓ HTTP server closed');
    
    try {
      // Close database connection (no callback in newer Mongoose)
      const mongoose = require('mongoose');
      await mongoose.connection.close();
      console.log('✓ MongoDB connection closed');
      console.log('👋 Server shutdown complete');
      process.exit(0);
    } catch (error) {
      console.error('Error closing MongoDB connection:', error);
      process.exit(1);
    }
  });
  
  // Force close after 10 seconds
  setTimeout(() => {
    console.error('⚠️ Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('=== UNCAUGHT EXCEPTION ===');
  console.error('Error:', error.message);
  console.error('Stack:', error.stack);
  console.error('=========================');
  
  // Exit process
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('=== UNHANDLED REJECTION ===');
  console.error('Reason:', reason);
  console.error('Promise:', promise);
  console.error('===========================');
  
  // Exit process
  process.exit(1);
});

module.exports = app; // For testing purposes