// utils/encryption.js
const crypto = require('crypto');

// Encryption settings
const ALGORITHM = 'aes-256-gcm';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const KEY_BUFFER = Buffer.from(ENCRYPTION_KEY.substring(0, 64), 'hex');

// Encrypt text
const encrypt = (text) => {
  if (!text) return null;
  
  try {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, KEY_BUFFER, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    // Return: iv:authTag:encrypted
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  } catch (error) {
    console.error('Encryption error:', error);
    return null;
  }
};

// Decrypt text
const decrypt = (encryptedText) => {
  if (!encryptedText) return null;
  
  try {
    const parts = encryptedText.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted format');
    }
    
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];
    
    const decipher = crypto.createDecipheriv(ALGORITHM, KEY_BUFFER, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Decryption error:', error);
    return null;
  }
};

// Test encryption on startup
const testEncryption = () => {
  const testString = 'test-encryption-123';
  const encrypted = encrypt(testString);
  const decrypted = decrypt(encrypted);
  
  if (decrypted === testString) {
    console.log('✅ Encryption test passed');
    return true;
  } else {
    console.error('❌ Encryption test failed');
    return false;
  }
};

module.exports = {
  encrypt,
  decrypt,
  testEncryption
};