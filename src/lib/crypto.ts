// Elliptic Curve Cryptography utilities using @noble/curves
import { p256 } from '@noble/curves/p256';

export interface ECPoint {
  x: string;
  y: string;
}

export interface ECKeyPair {
  privateKey: string;
  publicKey: ECPoint;
}

// Convert ArrayBuffer to hex string
export function arrayBufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  return '0x' + Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Convert hex string to ArrayBuffer
export function hexToArrayBuffer(hex: string): ArrayBuffer {
  const cleanHex = hex.replace('0x', '');
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
  }
  return bytes.buffer;
}

// Generate a random private key (32 bytes for secp256r1)
export function generatePrivateKey(): string {
  const privateKeyBytes = new Uint8Array(32);
  crypto.getRandomValues(privateKeyBytes);
  return arrayBufferToHex(privateKeyBytes.buffer);
}

// Extract coordinates from an EC public key
export async function extractPublicKeyCoordinates(publicKey: CryptoKey): Promise<ECPoint> {
  const rawKey = await crypto.subtle.exportKey('raw', publicKey);
  const keyBytes = new Uint8Array(rawKey);
  
  // For uncompressed format: 0x04 + 32 bytes x + 32 bytes y
  if (keyBytes[0] !== 0x04 || keyBytes.length !== 65) {
    throw new Error('Invalid public key format');
  }
  
  const x = arrayBufferToHex(keyBytes.slice(1, 33).buffer);
  const y = arrayBufferToHex(keyBytes.slice(33, 65).buffer);
  
  return { x, y };
}

// Create public key from coordinates
export async function createPublicKeyFromCoordinates(point: ECPoint): Promise<CryptoKey> {
  const xBytes = new Uint8Array(hexToArrayBuffer(point.x));
  const yBytes = new Uint8Array(hexToArrayBuffer(point.y));
  
  // Create uncompressed format: 0x04 + x + y
  const publicKeyBytes = new Uint8Array(65);
  publicKeyBytes[0] = 0x04;
  publicKeyBytes.set(xBytes, 1);
  publicKeyBytes.set(yBytes, 33);
  
  return await crypto.subtle.importKey(
    'raw',
    publicKeyBytes.buffer,
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    false,
    []
  );
}

// Generate EC key pair using @noble/curves
export async function generateECKeyPair(): Promise<ECKeyPair> {
  // Generate a random private key using crypto.getRandomValues
  const privateKeyBytes = new Uint8Array(32);
  crypto.getRandomValues(privateKeyBytes);
  const privateKey = arrayBufferToHex(privateKeyBytes.buffer);
  
  // Calculate the corresponding public key using real elliptic curve math
  const publicKey = await privateKeyToPublicKey(privateKey);
  
  return { privateKey, publicKey };
}

// Create private key from hex string - this is a limitation of Web Crypto API
// We can't directly import raw private keys, so we simulate the process
export async function createPrivateKeyFromHex(privateKeyHex: string): Promise<CryptoKey> {
  // Since Web Crypto API doesn't easily allow importing raw private keys,
  // we'll generate a key pair and use it as a proxy
  // In a real implementation, you'd need proper PKCS#8 formatting
  
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    ['deriveKey', 'deriveBits']
  );
  
  // Note: This doesn't actually use the privateKeyHex value
  // It's a limitation of the demo approach
  return keyPair.privateKey;
}

// Perform scalar multiplication: scalar * point using real elliptic curve math
export async function scalarMultiplication(scalar: string, point: ECPoint): Promise<ECPoint> {
  // Use the same ECDH function which now implements proper EC scalar multiplication
  return await performECDH(scalar, point);
}



// Perform ECDH operation using real elliptic curve scalar multiplication
// This performs actual EC math: privateKey * publicKeyPoint = sharedSecret
export async function performECDH(privateKeyHex: string, publicKeyPoint: ECPoint): Promise<ECPoint> {
  try {
    // Convert private key hex to BigInt
    const cleanPrivateHex = privateKeyHex.replace('0x', '');
    const privateKeyBigInt = BigInt('0x' + cleanPrivateHex);
    
    // Convert public key point coordinates to a Point object
    const cleanXHex = publicKeyPoint.x.replace('0x', '');
    const cleanYHex = publicKeyPoint.y.replace('0x', '');
    
    // Create uncompressed public key bytes: 0x04 + x + y
    const xBytes = new Uint8Array(32);
    const yBytes = new Uint8Array(32);
    
    for (let i = 0; i < 32; i++) {
      xBytes[i] = parseInt(cleanXHex.substr(i * 2, 2), 16);
      yBytes[i] = parseInt(cleanYHex.substr(i * 2, 2), 16);
    }
    
    const publicKeyBytes = new Uint8Array(65);
    publicKeyBytes[0] = 0x04; // Uncompressed format
    publicKeyBytes.set(xBytes, 1);
    publicKeyBytes.set(yBytes, 33);
    
    // Create Point from coordinates
    const point = p256.ProjectivePoint.fromHex(publicKeyBytes);
    
    // Perform scalar multiplication: privateKey * point
    const resultPoint = point.multiply(privateKeyBigInt);
    
    // Convert result back to affine coordinates
    const resultBytes = resultPoint.toRawBytes(false); // false = uncompressed
    const resultArray = new Uint8Array(resultBytes);
    
    if (resultArray[0] !== 0x04 || resultArray.length !== 65) {
      throw new Error('Invalid ECDH result format');
    }
    
    const resultXBytes = resultArray.slice(1, 33);
    const resultYBytes = resultArray.slice(33, 65);
    
    const x = '0x' + Array.from(resultXBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const y = '0x' + Array.from(resultYBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    
    return { x, y };
  } catch (error) {
    console.error('ECDH operation failed:', error);
    throw error;
  }
}

// Generate random blind value
export function generateBlind(): string {
  return generatePrivateKey();
}

// Convert private key to public key point using real elliptic curve scalar multiplication
export async function privateKeyToPublicKey(privateKeyHex: string): Promise<ECPoint> {
  // Remove 0x prefix if present and convert to BigInt
  const cleanHex = privateKeyHex.replace('0x', '');
  const privateKeyBigInt = BigInt('0x' + cleanHex);
  
  // Perform scalar multiplication: privateKey * G = PublicKey
  const publicKeyPoint = p256.getPublicKey(privateKeyBigInt, false); // false = uncompressed format
  
  // Extract x and y coordinates from the uncompressed public key
  // First byte is 0x04 for uncompressed format, then 32 bytes x, then 32 bytes y
  const publicKeyBytes = new Uint8Array(publicKeyPoint);
  
  if (publicKeyBytes[0] !== 0x04 || publicKeyBytes.length !== 65) {
    throw new Error(`Invalid public key format from @noble/curves: first byte=${publicKeyBytes[0].toString(16)}, length=${publicKeyBytes.length}`);
  }
  
  const xBytes = publicKeyBytes.slice(1, 33);
  const yBytes = publicKeyBytes.slice(33, 65);
  
  const x = '0x' + Array.from(xBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  const y = '0x' + Array.from(yBytes).map(b => b.toString(16).padStart(2, '0')).join('');
  
  return { x, y };
}

// Calculate [db]G = d * b * G using method 1: ECDH(d, [b]G)
export async function calculateDbG(hsmPrivateKey: string, blind: string): Promise<ECPoint> {
  // Method 1: Set b as private scalar and generate [b]G, then perform ECDH(d, [b]G)
  
  // Step 1: Generate [b]G from blind value b
  const blindPublicKey = await privateKeyToPublicKey(blind);
  
  // Step 2: Perform ECDH(d, [b]G) to get [db]G
  return await performECDH(hsmPrivateKey, blindPublicKey);
}
