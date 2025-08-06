// HKDF implementation using Web Crypto API

export async function hkdf(
  ikm: ArrayBuffer,
  salt: string = '',
  info: string = '',
  length: number = 32
): Promise<ArrayBuffer> {
  // Convert inputs
  const saltBytes = new TextEncoder().encode(salt);
  const infoBytes = new TextEncoder().encode(info);
  
  // Step 1: Extract
  const extractKey = await crypto.subtle.importKey(
    'raw',
    saltBytes.length > 0 ? saltBytes : new Uint8Array(32), // Use zero salt if empty
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const prk = await crypto.subtle.sign('HMAC', extractKey, ikm);
  
  // Step 2: Expand
  const expandKey = await crypto.subtle.importKey(
    'raw',
    prk,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const n = Math.ceil(length / 32); // SHA-256 output is 32 bytes
  let t = new Uint8Array(0);
  let okm = new Uint8Array(0);
  
  for (let i = 1; i <= n; i++) {
    const input = new Uint8Array(t.length + infoBytes.length + 1);
    input.set(t, 0);
    input.set(infoBytes, t.length);
    input[input.length - 1] = i;
    
    t = new Uint8Array(await crypto.subtle.sign('HMAC', expandKey, input));
    
    const newOkm = new Uint8Array(okm.length + t.length);
    newOkm.set(okm, 0);
    newOkm.set(t, okm.length);
    okm = newOkm;
  }
  
  return okm.slice(0, length).buffer;
}

export function arrayBufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  return '0x' + Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToArrayBuffer(hex: string): ArrayBuffer {
  const cleanHex = hex.replace('0x', '');
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
  }
  return bytes.buffer;
}

// HKDF with intermediate values returned for educational purposes
export async function hkdfWithSteps(
  ikm: ArrayBuffer,
  salt: string = '',
  info: string = '',
  length: number = 32
): Promise<{ prk: ArrayBuffer; okm: ArrayBuffer; prkHex: string; okmHex: string }> {
  // Convert inputs
  const saltBytes = new TextEncoder().encode(salt);
  const infoBytes = new TextEncoder().encode(info);
  
  // Step 1: Extract
  const extractKey = await crypto.subtle.importKey(
    'raw',
    saltBytes.length > 0 ? saltBytes : new Uint8Array(32), // Use zero salt if empty
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const prk = await crypto.subtle.sign('HMAC', extractKey, ikm);
  
  // Step 2: Expand
  const expandKey = await crypto.subtle.importKey(
    'raw',
    prk,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const n = Math.ceil(length / 32); // SHA-256 output is 32 bytes
  let t = new Uint8Array(0);
  let okm = new Uint8Array(0);
  
  for (let i = 1; i <= n; i++) {
    const input = new Uint8Array(t.length + infoBytes.length + 1);
    input.set(t, 0);
    input.set(infoBytes, t.length);
    input[input.length - 1] = i;
    
    t = new Uint8Array(await crypto.subtle.sign('HMAC', expandKey, input));
    
    const newOkm = new Uint8Array(okm.length + t.length);
    newOkm.set(okm, 0);
    newOkm.set(t, okm.length);
    okm = newOkm;
  }
  
  const finalOkm = okm.slice(0, length);
  
  return {
    prk,
    okm: finalOkm.buffer,
    prkHex: arrayBufferToHex(prk),
    okmHex: arrayBufferToHex(finalOkm.buffer)
  };
}
