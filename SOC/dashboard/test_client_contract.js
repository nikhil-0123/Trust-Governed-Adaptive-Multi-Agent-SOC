// TGAM-SOC Dashboard Client Contract Test
import assert from 'node:assert';

// Mock localStorage for node environment
globalThis.localStorage = {
  store: {},
  getItem(key) { return this.store[key] || null; },
  setItem(key, value) { this.store[key] = String(value); },
  removeItem(key) { delete this.store[key]; },
  clear() { this.store = {}; }
};

// Import client
const { getApiConfig, setApiConfig, resetApiConfig } = await import('./src/api/client.js');

console.log('Testing TGAM-SOC Dashboard Client Configuration...');

// 1. Defaults
resetApiConfig();
const def = getApiConfig();
assert.strictEqual(def.baseUrl, 'http://localhost:8000', 'Default baseUrl should be http://localhost:8000');
assert.strictEqual(def.token, 'dev-token-123', 'Default token should be dev-token-123');
console.log('[PASS] Default API configuration verified.');

// 2. Set Config
setApiConfig('http://192.168.1.100:8000/', 'custom-soc-token-xyz');
const custom = getApiConfig();
assert.strictEqual(custom.baseUrl, 'http://192.168.1.100:8000', 'Trailing slash should be trimmed');
assert.strictEqual(custom.token, 'custom-soc-token-xyz', 'Custom token should be stored');
console.log('[PASS] Custom API configuration and normalization verified.');

// 3. Reset
resetApiConfig();
const reset = getApiConfig();
assert.strictEqual(reset.baseUrl, 'http://localhost:8000', 'Reset should restore default baseUrl');
assert.strictEqual(reset.token, 'dev-token-123', 'Reset should restore default token');
console.log('[PASS] Reset API configuration verified.');

console.log('=== ALL CLIENT CONFIGURATION TESTS PASSED ===');
