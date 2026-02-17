// models/Sms.js

const mongoose = require('mongoose');

const smsSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  username: {
    type: String,
    required: true,
    index: true
  },
  domain: {
    type: String,
    required: true,
    index: true
  },
  destination: {
    type: String,
    required: true,
    index: true
  },
  fromNumber: {
    type: String,
    required: true,
    index: true
  },
  message: {
    type: String,
    required: true
  },
  messageLength: {
    type: Number,
    default: 0
  },
  messageSession: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  status: {
    type: String,
    enum: ['sent', 'delivered', 'failed', 'pending'],
    default: 'sent',
    index: true
  },
  direction: {
    type: String,
    enum: ['outbound', 'inbound'],
    default: 'outbound'
  },
  sentTime: {
    type: Date,
    default: Date.now,
    index: true
  },
  deliveredTime: {
    type: Date
  },
  failureReason: {
    type: String
  },
  segmentCount: {
    type: Number,
    default: 1
  },
  metadata: {
    userAgent: String,
    ipAddress: String,
    source: {
      type: String,
      default: 'chrome-extension'
    },
    apiResponse: mongoose.Schema.Types.Mixed
  }
}, {
  timestamps: true // Adds createdAt and updatedAt
});

// Indexes for performance
smsSchema.index({ userId: 1, sentTime: -1 });
smsSchema.index({ username: 1, sentTime: -1 });
smsSchema.index({ domain: 1, sentTime: -1 });
smsSchema.index({ destination: 1, sentTime: -1 });
smsSchema.index({ fromNumber: 1, sentTime: -1 });
smsSchema.index({ status: 1, sentTime: -1 });
smsSchema.index({ createdAt: -1 });

// Virtual for message preview (first 50 characters)
smsSchema.virtual('messagePreview').get(function() {
  if (!this.message) return '';
  return this.message.length > 50 
    ? this.message.substring(0, 50) + '...' 
    : this.message;
});

// Calculate segment count based on message length
smsSchema.pre('save', function(next) {
  if (this.message) {
    this.messageLength = this.message.length;
    
    // SMS segment calculation (160 chars for GSM-7, 70 for UCS-2/Unicode)
    // For simplicity, using 160 as standard
    if (this.messageLength <= 160) {
      this.segmentCount = 1;
    } else {
      // Multi-part messages use 153 characters per segment (7 chars for headers)
      this.segmentCount = Math.ceil(this.messageLength / 153);
    }
  }
  next();
});

// Method to update SMS status
smsSchema.methods.updateStatus = function(status, additionalData = {}) {
  this.status = status;
  
  if (status === 'delivered') {
    if (!this.deliveredTime) {
      this.deliveredTime = new Date();
    }
  }
  
  if (additionalData.failureReason) {
    this.failureReason = additionalData.failureReason;
  }
  
  if (additionalData.apiResponse) {
    this.metadata.apiResponse = additionalData.apiResponse;
  }
  
  return this.save();
};

// Static method to get SMS statistics for a user
smsSchema.statics.getSmsStats = async function(userId, dateRange = {}) {
  const matchQuery = { userId };
  
  if (dateRange.startDate || dateRange.endDate) {
    matchQuery.sentTime = {};
    if (dateRange.startDate) {
      matchQuery.sentTime.$gte = new Date(dateRange.startDate);
    }
    if (dateRange.endDate) {
      matchQuery.sentTime.$lte = new Date(dateRange.endDate);
    }
  }
  
  const stats = await this.aggregate([
    { $match: matchQuery },
    {
      $group: {
        _id: '$status',
        count: { $sum: 1 },
        totalSegments: { $sum: '$segmentCount' },
        totalCharacters: { $sum: '$messageLength' }
      }
    }
  ]);
  
  const totalMessages = await this.countDocuments(matchQuery);
  
  // Get most contacted numbers
  const topDestinations = await this.aggregate([
    { $match: matchQuery },
    {
      $group: {
        _id: '$destination',
        count: { $sum: 1 }
      }
    },
    { $sort: { count: -1 } },
    { $limit: 5 }
  ]);
  
  return {
    totalMessages,
    byStatus: stats,
    topDestinations,
    dateRange
  };
};

// Static method to get conversation history between user and a number
smsSchema.statics.getConversation = async function(userId, phoneNumber, limit = 50) {
  return this.find({
    userId: userId,
    $or: [
      { destination: phoneNumber },
      { fromNumber: phoneNumber }
    ]
  })
  .sort({ sentTime: -1 })
  .limit(limit)
  .lean();
};

module.exports = mongoose.model('Sms', smsSchema);