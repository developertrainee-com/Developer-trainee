// utils/phoneValidator.js
// Performance-optimized phone number validation
const phonePatterns = {
  // US: +1 (555) 123-4567, 555-123-4567, 5551234567
  us: /^(\+?1)?[\s.-]?\(?([0-9]{3})\)?[\s.-]?([0-9]{3})[\s.-]?([0-9]{4})$/,
  
  // International: +91 98765 43210, +44 20 7123 4567
  international: /^\+?[1-9]\d{1,14}$/,
  
  // Generic: Extract digits
  generic: /[\d\s\-\(\)\+\.]{7,}/
};

const validatePhoneNumber = (text) => {
  // Quick rejection of obviously invalid inputs
  if (!text || text.length < 7 || text.length > 20) {
    return null;
  }

  // Remove common non-digit characters for validation
  const digitsOnly = text.replace(/[\s\-\(\)\+\.]/g, '');
  
  // Must have between 7-15 digits
  if (digitsOnly.length < 7 || digitsOnly.length > 15) {
    return null;
  }

  // Check against patterns
  if (phonePatterns.us.test(text) || phonePatterns.international.test(digitsOnly)) {
    return digitsOnly;
  }

  return null;
};

const formatPhoneNumber = (phone) => {
  const digitsOnly = phone.replace(/\D/g, '');
  
  // US format
  if (digitsOnly.length === 10) {
    return `+1${digitsOnly}`;
  }
  
  // Already has country code
  if (digitsOnly.length === 11 && digitsOnly.startsWith('1')) {
    return `+${digitsOnly}`;
  }
  
  // International
  if (digitsOnly.length > 10) {
    return `+${digitsOnly}`;
  }
  
  return digitsOnly;
};

module.exports = {
  validatePhoneNumber,
  formatPhoneNumber
};