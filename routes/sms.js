// routes/sms.js

const express = require('express');
const router = express.Router();
const axios = require('axios');
const crypto = require('crypto');
const auth = require('../middleware/auth');
const authRoutes = require('./auth');
const Sms = require('../models/Sms');

// Get SMS numbers for domain
router.get('/numbers', auth, async (req, res) => {
  try {
    const user = req.user;

    console.log(`Fetching SMS numbers for domain: ${user.domain}`);

    // Get NetSapiens token (auto-refreshes if needed)
    const netsapiensToken = await authRoutes.getNetSapiensToken(user);

    const response = await axios.get(
      `${process.env.NETSAPIENS_API_URL}/domains/${user.domain}/smsnumbers`,
      {
        params: { dest: '*' },
        headers: {
          'Authorization': `Bearer ${netsapiensToken}`,
          'Accept': 'application/json'
        },
        timeout: 10000
      }
    );

    const smsNumbers = response.data || [];
    
    // Find user's default SMS number
    const userSmsNumber = smsNumbers.find(num => num.dest === user.user);

    res.json({
      success: true,
      numbers: smsNumbers,
      defaultNumber: userSmsNumber?.number || null,
      userNumber: user.user
    });

  } catch (error) {
    console.error('Failed to fetch SMS numbers:', error.response?.data || error.message);
    
    if (error.response?.status === 401) {
      return res.status(401).json({
        error: 'Session expired',
        needsReauth: true
      });
    }

    if (error.message === 'NetSapiens token refresh failed') {
      return res.status(401).json({
        error: 'Session expired, please login again',
        needsReauth: true
      });
    }

    res.status(error.response?.status || 500).json({
      error: 'Failed to fetch SMS numbers',
      message: error.response?.data?.message || error.message
    });
  }
});

// Send SMS
router.post('/send', auth, async (req, res) => {
  try {
    const { destination, message, fromNumber, messageSession } = req.body;
    const user = req.user;

    console.log('=== SMS SEND REQUEST ===');
    console.log('Request body:', req.body);
    console.log('User:', user.username);
    console.log('Domain:', user.domain);

    // Validation
    if (!destination || !message || !fromNumber) {
      console.error('Validation failed:', { destination: !!destination, message: !!message, fromNumber: !!fromNumber });
      return res.status(400).json({ 
        error: 'Missing required fields',
        details: 'destination, message, and fromNumber are required'
      });
    }

    if (message.length > 1600) {
      return res.status(400).json({ 
        error: 'Message too long',
        details: 'Message must be 1600 characters or less'
      });
    }

    // Clean destination number
    const cleanDestination = destination.replace(/^\+?1?/, '').replace(/\D/g, '');
    const cleanFromNumber = fromNumber.replace(/^\+?1?/, '').replace(/\D/g, '');

    console.log('Cleaned destination:', cleanDestination);
    console.log('Cleaned from number:', cleanFromNumber);

    // Generate message session ID
    const finalMessageSession = messageSession || generateMessageSessionId();
    console.log('Message session ID (length:', finalMessageSession.length + '):', finalMessageSession);

    // Create SMS record in database BEFORE sending
    const smsRecord = new Sms({
      userId: user._id,
      username: user.username,
      domain: user.domain,
      destination: cleanDestination,
      fromNumber: cleanFromNumber,
      message: message,
      messageSession: finalMessageSession,
      status: 'pending',
      direction: 'outbound',
      sentTime: new Date(),
      metadata: {
        userAgent: req.headers['user-agent'],
        source: 'chrome-extension'
      }
    });

    await smsRecord.save();
    console.log('✓ SMS record created in database:', smsRecord._id);

    const smsPayload = {
      type: 'sms',
      message: message,
      destination: cleanDestination,
      'from-number': cleanFromNumber
    };

    console.log('SMS Payload:', smsPayload);

    // Get NetSapiens token (auto-refreshes if needed)
    const netsapiensToken = await authRoutes.getNetSapiensToken(user);

    const apiUrl = `${process.env.NETSAPIENS_API_URL}/domains/${user.domain}/users/${user.user}/messagesessions/${finalMessageSession}/messages`;
    console.log('NetSapiens API URL:', apiUrl);

    const response = await axios.post(
      apiUrl,
      smsPayload,
      {
        headers: {
          'Authorization': `Bearer ${netsapiensToken}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        timeout: 15000,
        validateStatus: function (status) {
          return status >= 200 && status < 600;
        }
      }
    );

    console.log('NetSapiens Response Status:', response.status);
    console.log('NetSapiens Response Data:', JSON.stringify(response.data, null, 2));

    if (response.status >= 200 && response.status < 300) {
      // Update SMS record with success
      smsRecord.status = 'sent';
      smsRecord.metadata.apiResponse = response.data;
      await smsRecord.save();
      console.log('✓ SMS status updated to sent');

      console.log('SMS sent successfully!');
    } else {
      // Update SMS record with failure
      smsRecord.status = 'failed';
      smsRecord.failureReason = response.data?.message || response.data?.error || 'NetSapiens API error';
      smsRecord.metadata.apiResponse = response.data;
      await smsRecord.save();
      console.log('✗ SMS failed, status updated');

      console.error('NetSapiens API Error:', response.data);
      return res.status(response.status).json({
        error: 'Failed to send SMS',
        message: response.data?.message || response.data?.error || 'NetSapiens API error',
        details: response.data,
        smsRecordId: smsRecord._id
      });
    }

    // Also save to user's SMS history for backward compatibility
    setImmediate(() => {
      if (!user.smsHistory) user.smsHistory = [];
      user.smsHistory.push({
        destination: cleanDestination,
        fromNumber: cleanFromNumber,
        message: message.substring(0, 100),
        timestamp: new Date(),
        messageSession: finalMessageSession
      });
      if (user.smsHistory.length > 50) {
        user.smsHistory = user.smsHistory.slice(-50);
      }
      user.save().catch(err => console.error('Failed to save to user SMS history:', err));
    });

    res.json({
      success: true,
      message: 'SMS sent successfully',
      messageSession: finalMessageSession,
      smsRecordId: smsRecord._id,
      segmentCount: smsRecord.segmentCount,
      data: response.data
    });

  } catch (error) {
    console.error('=== SMS SEND ERROR ===');
    console.error('Error message:', error.message);
    console.error('Error response:', error.response?.data);
    console.error('Error status:', error.response?.status);
    
    // Update SMS record with error if it exists
    if (req.body.messageSession) {
      Sms.findOne({ messageSession: req.body.messageSession })
        .then(sms => {
          if (sms) {
            sms.updateStatus('failed', { 
              failureReason: error.response?.data?.message || error.message 
            });
          }
        })
        .catch(err => console.error('Failed to update SMS status:', err));
    }
    
    if (error.response?.status === 401) {
      return res.status(401).json({
        error: 'Session expired',
        needsReauth: true
      });
    }

    if (error.message === 'NetSapiens token refresh failed') {
      return res.status(401).json({
        error: 'Session expired, please login again',
        needsReauth: true
      });
    }

    if (error.code === 'ECONNREFUSED') {
      return res.status(503).json({
        error: 'Cannot connect to NetSapiens',
        message: 'NetSapiens API is not reachable'
      });
    }

    if (error.code === 'ETIMEDOUT') {
      return res.status(504).json({
        error: 'Request timeout',
        message: 'NetSapiens API did not respond in time'
      });
    }

    res.status(error.response?.status || 500).json({
      error: 'Failed to send SMS',
      message: error.response?.data?.message || error.message,
      details: error.response?.data
    });
  }
});

// Helper function to generate 32-character random message session ID
function generateMessageSessionId() {
  return crypto.randomBytes(16).toString('hex');
}

// Get SMS history with advanced filtering
router.get('/history', auth, async (req, res) => {
  try {
    const { 
      limit = 20, 
      page = 1, 
      status, 
      startDate, 
      endDate,
      destination,
      fromNumber
    } = req.query;

    const query = { userId: req.user._id };

    // Add filters
    if (status) {
      query.status = status;
    }

    if (destination) {
      query.destination = { $regex: destination, $options: 'i' };
    }

    if (fromNumber) {
      query.fromNumber = { $regex: fromNumber, $options: 'i' };
    }

    if (startDate || endDate) {
      query.sentTime = {};
      if (startDate) {
        query.sentTime.$gte = new Date(startDate);
      }
      if (endDate) {
        query.sentTime.$lte = new Date(endDate);
      }
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [messages, totalCount] = await Promise.all([
      Sms.find(query)
        .sort({ sentTime: -1 })
        .limit(parseInt(limit))
        .skip(skip)
        .lean(),
      Sms.countDocuments(query)
    ]);

    // Also get legacy SMS history from user document for backward compatibility
    const legacyHistory = (req.user.smsHistory || [])
      .slice(-parseInt(limit))
      .reverse();

    res.json({
      success: true,
      messages: messages,
      legacyHistory: legacyHistory,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        totalCount,
        totalPages: Math.ceil(totalCount / parseInt(limit))
      }
    });

  } catch (error) {
    console.error('Get SMS history error:', error);
    res.status(500).json({ error: 'Failed to retrieve SMS history' });
  }
});

// Get SMS statistics
router.get('/stats', auth, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;

    const dateRange = {};
    if (startDate) dateRange.startDate = startDate;
    if (endDate) dateRange.endDate = endDate;

    const stats = await Sms.getSmsStats(req.user._id, dateRange);

    res.json({
      success: true,
      stats
    });

  } catch (error) {
    console.error('Get SMS stats error:', error);
    res.status(500).json({ error: 'Failed to retrieve SMS statistics' });
  }
});

// Get specific SMS details
router.get('/:messageSession', auth, async (req, res) => {
  try {
    const { messageSession } = req.params;

    const sms = await Sms.findOne({ 
      messageSession: messageSession,
      userId: req.user._id 
    });

    if (!sms) {
      return res.status(404).json({ 
        error: 'SMS not found' 
      });
    }

    res.json({
      success: true,
      sms
    });

  } catch (error) {
    console.error('Get SMS details error:', error);
    res.status(500).json({ error: 'Failed to retrieve SMS details' });
  }
});

// Get conversation with a specific number
router.get('/conversation/:phoneNumber', auth, async (req, res) => {
  try {
    const { phoneNumber } = req.params;
    const { limit = 50 } = req.query;

    const conversation = await Sms.getConversation(
      req.user._id, 
      phoneNumber, 
      parseInt(limit)
    );

    res.json({
      success: true,
      phoneNumber: phoneNumber,
      messageCount: conversation.length,
      messages: conversation
    });

  } catch (error) {
    console.error('Get conversation error:', error);
    res.status(500).json({ error: 'Failed to retrieve conversation' });
  }
});

// Update SMS status (for webhooks or manual updates)
router.patch('/:messageSession/status', auth, async (req, res) => {
  try {
    const { messageSession } = req.params;
    const { status, deliveredTime, failureReason } = req.body;

    const sms = await Sms.findOne({ 
      messageSession: messageSession,
      userId: req.user._id 
    });

    if (!sms) {
      return res.status(404).json({ 
        error: 'SMS not found' 
      });
    }

    // Update status
    if (status) {
      sms.status = status;
    }

    // Update delivered time
    if (deliveredTime) {
      sms.deliveredTime = new Date(deliveredTime);
    } else if (status === 'delivered' && !sms.deliveredTime) {
      sms.deliveredTime = new Date();
    }

    // Update failure reason
    if (failureReason) {
      sms.failureReason = failureReason;
    }

    await sms.save();

    console.log('✓ SMS status updated:', messageSession, '->', status);

    res.json({
      success: true,
      sms
    });

  } catch (error) {
    console.error('Update SMS status error:', error);
    res.status(500).json({ error: 'Failed to update SMS status' });
  }
});

// Delete SMS record (admin only or for testing)
router.delete('/:messageSession', auth, async (req, res) => {
  try {
    const { messageSession } = req.params;

    const sms = await Sms.findOneAndDelete({ 
      messageSession: messageSession,
      userId: req.user._id 
    });

    if (!sms) {
      return res.status(404).json({ 
        error: 'SMS not found' 
      });
    }

    res.json({
      success: true,
      message: 'SMS record deleted successfully'
    });

  } catch (error) {
    console.error('Delete SMS error:', error);
    res.status(500).json({ error: 'Failed to delete SMS record' });
  }
});

module.exports = router;