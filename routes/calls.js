// routes/calls.js

const express = require('express');
const router = express.Router();
const axios = require('axios');
const auth = require('../middleware/auth');
const authRoutes = require('./auth');
const Call = require('../models/Call');
const { validatePhoneNumber, formatPhoneNumber } = require('../utils/phoneValidator');
const NodeCache = require('node-cache');

// Cache for rate limiting per user
const callCache = new NodeCache({ stdTTL: 60, checkperiod: 120 });

// Get phone numbers (caller IDs) for domain
router.get('/phonenumbers', auth, async (req, res) => {
  try {
    const user = req.user;

    console.log(`=== Fetching phone numbers for domain: ${user.domain} ===`);
    console.log('User:', user.user);

    // Get NetSapiens token (auto-refreshes if needed)
    const netsapiensToken = await authRoutes.getNetSapiensToken(user);

    const apiUrl = `${process.env.NETSAPIENS_API_URL}/domains/${user.domain}/phonenumbers`;
    console.log('API URL:', apiUrl);

    const response = await axios.get(apiUrl, {
      headers: {
        'Authorization': `Bearer ${netsapiensToken}`,
        'Accept': 'application/json'
      },
      timeout: 10000
    });

    console.log('Response status:', response.status);
    console.log('Response data type:', typeof response.data);
    console.log('Is array:', Array.isArray(response.data));
    console.log('Phone numbers count:', Array.isArray(response.data) ? response.data.length : 0);

    // Handle different response structures
    let phoneNumbers = [];
    
    if (Array.isArray(response.data)) {
      phoneNumbers = response.data;
    } else if (response.data && Array.isArray(response.data.phonenumbers)) {
      phoneNumbers = response.data.phonenumbers;
    } else if (response.data && typeof response.data === 'object') {
      phoneNumbers = Object.values(response.data).filter(item => 
        item && typeof item === 'object' && item.phonenumber
      );
    }

    console.log('Extracted phone numbers count:', phoneNumbers.length);
    
    const userPhoneNumber = phoneNumbers.find(num => 
      num['dial-rule-translation-destination-user'] === user.user ||
      num.user === user.user ||
      num.dest === user.user
    );

    const defaultPhoneNumber = userPhoneNumber?.phonenumber || null;
    
    console.log('Default phone number:', defaultPhoneNumber);

    res.json({
      success: true,
      phoneNumbers: phoneNumbers,
      defaultPhoneNumber: defaultPhoneNumber,
      userNumber: user.user
    });

  } catch (error) {
    console.error('=== Failed to fetch phone numbers ===');
    console.error('Error message:', error.message);
    console.error('Error response status:', error.response?.status);
    console.error('Error response data:', JSON.stringify(error.response?.data, null, 2));
    
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
      error: 'Failed to fetch phone numbers',
      message: error.response?.data?.message || error.message,
      details: error.response?.data
    });
  }
});

// Validate phone number endpoint
router.post('/validate', auth, async (req, res) => {
  try {
    const { phoneNumber } = req.body;

    if (!phoneNumber) {
      return res.status(400).json({ error: 'Phone number required' });
    }

    const validated = validatePhoneNumber(phoneNumber);

    if (validated) {
      res.json({
        valid: true,
        formatted: formatPhoneNumber(validated),
        original: phoneNumber
      });
    } else {
      res.json({
        valid: false,
        original: phoneNumber
      });
    }

  } catch (error) {
    console.error('Phone validation error:', error);
    res.status(500).json({ error: 'Validation failed' });
  }
});

// Initiate call endpoint
router.post('/initiate', auth, async (req, res) => {
  try {
    const { destination, callId, callerIdNumber, autoAnswerEnabled } = req.body;
    const user = req.user;

    console.log('=== Call Initiation Request ===');
    console.log('User:', user.user);
    console.log('Domain:', user.domain);
    console.log('Destination:', destination);
    console.log('Caller ID:', callerIdNumber);
    console.log('Auto Answer:', autoAnswerEnabled);

    if (!destination) {
      return res.status(400).json({ error: 'Destination number required' });
    }

    // Rate limiting: max 10 calls per minute per user
    const cacheKey = `call_limit_${user._id}`;
    const callCount = callCache.get(cacheKey) || 0;

    if (callCount >= 10) {
      return res.status(429).json({ 
        error: 'Rate limit exceeded. Please wait before making another call.' 
      });
    }

    // Validate phone number
    const validatedNumber = validatePhoneNumber(destination);
    if (!validatedNumber) {
      return res.status(400).json({ error: 'Invalid phone number format' });
    }

    const formattedDestination = formatPhoneNumber(validatedNumber);
    const finalCallId = callId || `call_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // Build call payload
    const callPayload = {
      synchronous: 'no',
      'call-id': finalCallId,
      destination: formattedDestination
    };

    // Add caller ID if provided
    if (callerIdNumber && callerIdNumber !== 'default') {
      callPayload['caller-id-number'] = callerIdNumber;
      console.log('Using custom caller ID:', callerIdNumber);
    }

    // Add auto-answer if enabled
    if (autoAnswerEnabled === true || autoAnswerEnabled === 'true' || autoAnswerEnabled === 'yes') {
      callPayload['auto-answer-enabled'] = 'yes';
      callPayload['auto-answer'] = 'yes';
      callPayload['Auto-Answer-Enabled'] = 'yes';
      console.log('Auto-answer enabled for caller phone');
    } else {
      callPayload['auto-answer-enabled'] = 'no';
    }

    // Create call record in database BEFORE making the API call
    const callRecord = new Call({
      userId: user._id,
      username: user.username,
      domain: user.domain,
      destination: formattedDestination,
      callId: finalCallId,
      callerIdNumber: callerIdNumber || 'default',
      autoAnswerEnabled: autoAnswerEnabled ? 'yes' : 'no',
      status: 'initiated',
      direction: 'outbound',
      startTime: new Date(),
      metadata: {
        userAgent: req.headers['user-agent'],
        source: 'chrome-extension'
      }
    });

    await callRecord.save();
    console.log('✓ Call record created in database:', callRecord._id);

    // Get NetSapiens token (auto-refreshes if needed)
    const netsapiensToken = await authRoutes.getNetSapiensToken(user);

    const apiUrl = `${process.env.NETSAPIENS_API_URL}/domains/${user.domain}/users/${user.user}/calls`;
    console.log('API URL:', apiUrl);
    console.log('Call payload:', JSON.stringify(callPayload, null, 2));

    // Make call to NetSapiens API
    const callResponse = await axios.post(
      apiUrl,
      callPayload,
      {
        headers: {
          'Authorization': `Bearer ${netsapiensToken}`,
          'Content-Type': 'application/json'
        },
        timeout: 10000
      }
    );

    console.log('Call initiated successfully');
    console.log('Call response:', JSON.stringify(callResponse.data, null, 2));

    // Update call record with response
    if (callResponse.data.code && callResponse.data.code >= 200 && callResponse.data.code < 300) {
      callRecord.status = 'ringing';
      await callRecord.save();
      console.log('✓ Call status updated to ringing');
    }

    // Update rate limiting
    callCache.set(cacheKey, callCount + 1);

    // Also save to user's call history for backward compatibility
    setImmediate(() => {
      user.callHistory.push({
        destination: formattedDestination,
        callId: finalCallId,
        callerIdNumber: callerIdNumber || 'default',
        autoAnswerEnabled: autoAnswerEnabled ? 'yes' : 'no',
        status: 'initiated',
        timestamp: new Date()
      });
      user.save().catch(err => console.error('Failed to save to user call history:', err));
    });

    res.json({
      success: true,
      code: callResponse.data.code || 202,
      message: callResponse.data.message || 'Call initiated successfully',
      callId: finalCallId,
      callRecordId: callRecord._id,
      destination: formattedDestination,
      callerIdNumber: callerIdNumber || 'default',
      autoAnswerEnabled: autoAnswerEnabled ? 'yes' : 'no'
    });

  } catch (error) {
    console.error('=== Call initiation error ===');
    console.error('Error message:', error.message);
    console.error('Error response status:', error.response?.status);
    console.error('Error response data:', JSON.stringify(error.response?.data, null, 2));
    
    // Update call record with failure
    if (req.body.callId) {
      Call.findOne({ callId: req.body.callId })
        .then(call => {
          if (call) {
            call.updateStatus('failed', { 
              failureReason: error.response?.data?.message || error.message 
            });
          }
        })
        .catch(err => console.error('Failed to update call status:', err));
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

    res.status(error.response?.status || 500).json({
      error: 'Failed to initiate call',
      message: error.response?.data?.message || error.message
    });
  }
});

// Get call history with advanced filtering
router.get('/history', auth, async (req, res) => {
  try {
    const { 
      limit = 20, 
      page = 1, 
      status, 
      startDate, 
      endDate,
      destination 
    } = req.query;

    const query = { userId: req.user._id };

    // Add filters
    if (status) {
      query.status = status;
    }

    if (destination) {
      query.destination = { $regex: destination, $options: 'i' };
    }

    if (startDate || endDate) {
      query.startTime = {};
      if (startDate) {
        query.startTime.$gte = new Date(startDate);
      }
      if (endDate) {
        query.startTime.$lte = new Date(endDate);
      }
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [calls, totalCount] = await Promise.all([
      Call.find(query)
        .sort({ startTime: -1 })
        .limit(parseInt(limit))
        .skip(skip)
        .lean(),
      Call.countDocuments(query)
    ]);

    // Also get legacy call history from user document for backward compatibility
    const legacyHistory = req.user.callHistory
      .slice(-parseInt(limit))
      .reverse();

    res.json({
      success: true,
      calls: calls,
      legacyHistory: legacyHistory,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        totalCount,
        totalPages: Math.ceil(totalCount / parseInt(limit))
      }
    });

  } catch (error) {
    console.error('Get call history error:', error);
    res.status(500).json({ error: 'Failed to retrieve call history' });
  }
});

// Get call statistics
router.get('/stats', auth, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;

    const dateRange = {};
    if (startDate) dateRange.startDate = startDate;
    if (endDate) dateRange.endDate = endDate;

    const stats = await Call.getCallStats(req.user._id, dateRange);

    res.json({
      success: true,
      stats
    });

  } catch (error) {
    console.error('Get call stats error:', error);
    res.status(500).json({ error: 'Failed to retrieve call statistics' });
  }
});

// Get specific call details
router.get('/:callId', auth, async (req, res) => {
  try {
    const { callId } = req.params;

    const call = await Call.findOne({ 
      callId: callId,
      userId: req.user._id 
    });

    if (!call) {
      return res.status(404).json({ 
        error: 'Call not found' 
      });
    }

    res.json({
      success: true,
      call
    });

  } catch (error) {
    console.error('Get call details error:', error);
    res.status(500).json({ error: 'Failed to retrieve call details' });
  }
});

// Update call status (for webhooks or manual updates)
router.patch('/:callId/status', auth, async (req, res) => {
  try {
    const { callId } = req.params;
    const { status, endTime, duration, recordingUrl, failureReason } = req.body;

    const call = await Call.findOne({ 
      callId: callId,
      userId: req.user._id 
    });

    if (!call) {
      return res.status(404).json({ 
        error: 'Call not found' 
      });
    }

    // Update status
    if (status) {
      call.status = status;
    }

    // Update end time
    if (endTime) {
      call.endTime = new Date(endTime);
    }

    // Update duration
    if (duration) {
      call.duration = parseInt(duration);
    } else if (call.startTime && call.endTime) {
      call.calculateDuration();
    }

    // Update recording URL
    if (recordingUrl) {
      call.recordingUrl = recordingUrl;
    }

    // Update failure reason
    if (failureReason) {
      call.failureReason = failureReason;
    }

    await call.save();

    console.log('✓ Call status updated:', callId, '->', status);

    res.json({
      success: true,
      call
    });

  } catch (error) {
    console.error('Update call status error:', error);
    res.status(500).json({ error: 'Failed to update call status' });
  }
});

// Delete call record (admin only or for testing)
router.delete('/:callId', auth, async (req, res) => {
  try {
    const { callId } = req.params;

    const call = await Call.findOneAndDelete({ 
      callId: callId,
      userId: req.user._id 
    });

    if (!call) {
      return res.status(404).json({ 
        error: 'Call not found' 
      });
    }

    res.json({
      success: true,
      message: 'Call record deleted successfully'
    });

  } catch (error) {
    console.error('Delete call error:', error);
    res.status(500).json({ error: 'Failed to delete call record' });
  }
});

module.exports = router;