// models/Call.js

const mongoose = require('mongoose');

const callSchema = new mongoose.Schema({
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
  callId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  callerIdNumber: {
    type: String,
    default: 'default'
  },
  autoAnswerEnabled: {
    type: String,
    enum: ['yes', 'no'],
    default: 'no'
  },
  status: {
    type: String,
    enum: ['initiated', 'ringing', 'answered', 'completed', 'failed', 'busy', 'no-answer', 'cancelled'],
    default: 'initiated',
    index: true
  },
  direction: {
    type: String,
    enum: ['outbound', 'inbound'],
    default: 'outbound'
  },
  startTime: {
    type: Date,
    default: Date.now,
    index: true
  },
  endTime: {
    type: Date
  },
  duration: {
    type: Number, // Duration in seconds
    default: 0
  },
  recordingUrl: {
    type: String
  },
  failureReason: {
    type: String
  },
  metadata: {
    userAgent: String,
    ipAddress: String,
    source: {
      type: String,
      default: 'chrome-extension'
    }
  }
}, {
  timestamps: true // Adds createdAt and updatedAt
});

// Indexes for performance
callSchema.index({ userId: 1, startTime: -1 });
callSchema.index({ username: 1, startTime: -1 });
callSchema.index({ domain: 1, startTime: -1 });
callSchema.index({ destination: 1, startTime: -1 });
callSchema.index({ status: 1, startTime: -1 });
callSchema.index({ createdAt: -1 });

// Virtual for call duration formatted
callSchema.virtual('durationFormatted').get(function() {
  if (!this.duration) return '0s';
  
  const hours = Math.floor(this.duration / 3600);
  const minutes = Math.floor((this.duration % 3600) / 60);
  const seconds = this.duration % 60;
  
  if (hours > 0) {
    return `${hours}h ${minutes}m ${seconds}s`;
  } else if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  } else {
    return `${seconds}s`;
  }
});

// Method to calculate duration
callSchema.methods.calculateDuration = function() {
  if (this.startTime && this.endTime) {
    this.duration = Math.floor((this.endTime - this.startTime) / 1000);
  }
  return this.duration;
};

// Method to update call status
callSchema.methods.updateStatus = function(status, additionalData = {}) {
  this.status = status;
  
  if (status === 'completed' || status === 'failed' || status === 'busy' || status === 'no-answer') {
    if (!this.endTime) {
      this.endTime = new Date();
      this.calculateDuration();
    }
  }
  
  if (additionalData.failureReason) {
    this.failureReason = additionalData.failureReason;
  }
  
  if (additionalData.recordingUrl) {
    this.recordingUrl = additionalData.recordingUrl;
  }
  
  return this.save();
};

// Static method to get call statistics for a user
callSchema.statics.getCallStats = async function(userId, dateRange = {}) {
  const matchQuery = { userId };
  
  if (dateRange.startDate || dateRange.endDate) {
    matchQuery.startTime = {};
    if (dateRange.startDate) {
      matchQuery.startTime.$gte = new Date(dateRange.startDate);
    }
    if (dateRange.endDate) {
      matchQuery.startTime.$lte = new Date(dateRange.endDate);
    }
  }
  
  const stats = await this.aggregate([
    { $match: matchQuery },
    {
      $group: {
        _id: '$status',
        count: { $sum: 1 },
        totalDuration: { $sum: '$duration' }
      }
    }
  ]);
  
  const totalCalls = await this.countDocuments(matchQuery);
  
  return {
    totalCalls,
    byStatus: stats,
    dateRange
  };
};

module.exports = mongoose.model('Call', callSchema);