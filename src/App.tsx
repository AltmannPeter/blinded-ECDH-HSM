import { useState, useCallback, useEffect } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { StepCard } from "@/components/step-card";
import { CryptoInput } from "@/components/crypto-input";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { 
  Shield, 
  AlertTriangle, 
  ShieldQuestion, 
  UserCheck, 
  RefreshCw, 
  Eye, 
  EyeOff,
  Dice1, 
  Calculator, 
  Cpu, 
  Key, 
  FileSignature, 
  CheckCircle2,
  RotateCcw,
  ArrowRight,
  ArrowDown,
  Info
} from "lucide-react";
import * as cryptoLib from "@/lib/crypto";
import { hkdf, hkdfWithSteps, arrayBufferToHex, hexToArrayBuffer } from "@/lib/hkdf";
import { SignJWT, jwtVerify } from "jose";

interface CryptoState {
  // Step 1: Key pairs
  hsmPrivateKey: string;
  hsmPublicKey: cryptoLib.ECPoint;
  validatorPrivateKey: string;
  validatorPublicKey: cryptoLib.ECPoint;
  hsmKeyRevealed: boolean;
  
  // Step 2: Blinding
  blind: string;
  blindedValidatorPublicKey: cryptoLib.ECPoint;
  
  // Step 3: HSM ECDH
  hsmEcdhResult: cryptoLib.ECPoint;
  
  // Step 4: HKDF
  hkdfSalt: string;
  hkdfInfo: string;
  hkdfPrk: string;
  hmacKey: string;
  
  // Step 5: JWT
  jwtPayload: string;
  jwt: string;
  dbPublicKey: cryptoLib.ECPoint;
  
  // Step 6: Validator operations
  validatorEcdhResult: cryptoLib.ECPoint;
  validatorHmacKey: string;
  validationResult: string;
}

export default function Demo() {
  const [state, setState] = useState<CryptoState>({
    hsmPrivateKey: '',
    hsmPublicKey: { x: '', y: '' },
    validatorPrivateKey: '',
    validatorPublicKey: { x: '', y: '' },
    hsmKeyRevealed: false,
    blind: '',
    blindedValidatorPublicKey: { x: '', y: '' },
    hsmEcdhResult: { x: '', y: '' },
    hkdfSalt: '',
    hkdfInfo: 'HS256 signature key',
    hkdfPrk: '',
    hmacKey: '',
    jwtPayload: JSON.stringify({ sub: 'user123', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 }, null, 2),
    jwt: '',
    dbPublicKey: { x: '', y: '' },
    validatorEcdhResult: { x: '', y: '' },
    validatorHmacKey: '',
    validationResult: ''
  });



  const resetAll = useCallback(() => {
    setState({
      hsmPrivateKey: '',
      hsmPublicKey: { x: '', y: '' },
      validatorPrivateKey: '',
      validatorPublicKey: { x: '', y: '' },
      hsmKeyRevealed: false,
      blind: '',
      blindedValidatorPublicKey: { x: '', y: '' },
      hsmEcdhResult: { x: '', y: '' },
      hkdfSalt: '',
      hkdfInfo: 'HS256 signature key',
      hkdfPrk: '',
      hmacKey: '',
      jwtPayload: JSON.stringify({ sub: 'user123', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 }, null, 2),
      jwt: '',
      dbPublicKey: { x: '', y: '' },
      validatorEcdhResult: { x: '', y: '' },
      validatorHmacKey: '',
      validationResult: ''
    });
  }, []);

  const generateKeys = useCallback(async () => {
    try {
      const hsmKeyPair = await cryptoLib.generateECKeyPair();
      const validatorKeyPair = await cryptoLib.generateECKeyPair();
      
      setState(prev => ({
        ...prev,
        hsmPrivateKey: hsmKeyPair.privateKey,
        hsmPublicKey: hsmKeyPair.publicKey,
        validatorPrivateKey: validatorKeyPair.privateKey,
        validatorPublicKey: validatorKeyPair.publicKey,
        hsmKeyRevealed: false
      }));
    } catch (error) {
      console.error('Key generation failed:', error);
    }
  }, []);

  const toggleHSMKeyVisibility = useCallback(() => {
    setState(prev => ({ ...prev, hsmKeyRevealed: !prev.hsmKeyRevealed }));
  }, []);

  const generateBlind = useCallback(async () => {
    const blind = cryptoLib.generateBlind();
    setState(prev => ({ 
      ...prev, 
      blind,
      blindedValidatorPublicKey: { x: '', y: '' }, // Clear previous blinded key
      hsmEcdhResult: { x: '', y: '' }, // Clear HSM ECDH result from Step 3
      hkdfPrk: '', // Clear HKDF PRK from Step 4
      hmacKey: '', // Clear derived HMAC key from Step 4
      jwtPayload: JSON.stringify({ sub: 'user123', iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 }, null, 2), // Reset JWT payload
      jwt: '', // Clear JWT from Step 5
      dbPublicKey: { x: '', y: '' }, // Clear [db]G public key for validator (will be regenerated in Step 2)
      validatorEcdhResult: { x: '', y: '' }, // Clear validator ECDH result from Step 6
      validatorHmacKey: '', // Clear validator HMAC key from Step 6
      validationResult: '' // Clear validation result from Step 6
    }));
    
    // Auto-apply blinding if validator public key exists
    if (state.validatorPublicKey.x) {
      try {
        const blindedKey = await cryptoLib.scalarMultiplication(blind, state.validatorPublicKey);
        setState(prev => ({ ...prev, blindedValidatorPublicKey: blindedKey }));
      } catch (error) {
        console.error('Auto-blinding failed:', error);
      }
    }
  }, [state.validatorPublicKey]);

  const applyBlinding = useCallback(async () => {
    if (!state.blind || !state.validatorPublicKey.x) return;
    
    try {
      const blindedKey = await cryptoLib.scalarMultiplication(state.blind, state.validatorPublicKey);
      setState(prev => ({ ...prev, blindedValidatorPublicKey: blindedKey }));
    } catch (error) {
      console.error('Blinding failed:', error);
    }
  }, [state.blind, state.validatorPublicKey]);

  const performHSMECDH = useCallback(async () => {
    if (!state.hsmPrivateKey || !state.blindedValidatorPublicKey.x) return;
    
    try {
      const result = await cryptoLib.performECDH(state.hsmPrivateKey, state.blindedValidatorPublicKey);
      setState(prev => ({ ...prev, hsmEcdhResult: result }));
    } catch (error) {
      console.error('HSM ECDH failed:', error);
    }
  }, [state.hsmPrivateKey, state.blindedValidatorPublicKey]);

  const deriveHMACKey = useCallback(async () => {
    if (!state.hsmEcdhResult.x) return;
    
    try {
      const ikm = hexToArrayBuffer(state.hsmEcdhResult.x);
      const result = await hkdfWithSteps(ikm, state.hkdfSalt, state.hkdfInfo, 32);
      
      setState(prev => ({ 
        ...prev, 
        hkdfPrk: result.prkHex,
        hmacKey: result.okmHex 
      }));
    } catch (error) {
      console.error('HKDF failed:', error);
    }
  }, [state.hsmEcdhResult.x, state.hkdfSalt, state.hkdfInfo]);

  const updateHkdfSalt = useCallback((salt: string) => {
    setState(prev => ({ 
      ...prev, 
      hkdfSalt: salt, 
      hkdfPrk: '', 
      hmacKey: '', 
      validatorHmacKey: '', // Clear validator HMAC key since it depends on HKDF parameters
      validationResult: '' // Clear validation result
    }));
  }, []);

  const updateHkdfInfo = useCallback((info: string) => {
    setState(prev => ({ 
      ...prev, 
      hkdfInfo: info, 
      hkdfPrk: '', 
      hmacKey: '', 
      validatorHmacKey: '', // Clear validator HMAC key since it depends on HKDF parameters
      validationResult: '' // Clear validation result
    }));
  }, []);

  const updateJwtPayload = useCallback((payload: string) => {
    setState(prev => ({ ...prev, jwtPayload: payload, jwt: '' }));
  }, []);

  const generateDbG = useCallback(async () => {
    if (!state.hsmPrivateKey || !state.blind) return;
    
    try {
      // Calculate [db]G = d * b * G for validator
      const dbPoint = await cryptoLib.calculateDbG(state.hsmPrivateKey, state.blind);
      setState(prev => ({ ...prev, dbPublicKey: dbPoint }));
    } catch (error) {
      console.error('[db]G generation failed:', error);
    }
  }, [state.hsmPrivateKey, state.blind]);

  const signJWT = useCallback(async () => {
    if (!state.hmacKey) return;
    
    try {
      // Parse JWT payload
      let payload;
      try {
        payload = JSON.parse(state.jwtPayload);
      } catch (error) {
        console.error('Invalid JWT payload JSON:', error);
        return;
      }

      // Create HMAC key for signing
      const keyBytes = hexToArrayBuffer(state.hmacKey);
      
      // Sign JWT
      const jwt = await new SignJWT(payload)
        .setProtectedHeader({ alg: 'HS256' })
        .sign(new Uint8Array(keyBytes));
      
      setState(prev => ({ ...prev, jwt }));
    } catch (error) {
      console.error('JWT signing failed:', error);
    }
  }, [state.hmacKey, state.jwtPayload]);

  const performValidatorECDH = useCallback(async () => {
    if (!state.validatorPrivateKey || !state.dbPublicKey.x) return;
    
    try {
      const result = await cryptoLib.performECDH(state.validatorPrivateKey, state.dbPublicKey);
      
      // Derive HMAC key using same HKDF parameters as Step 4
      const ikm = hexToArrayBuffer(result.x);
      const derivedKey = await hkdf(ikm, state.hkdfSalt, state.hkdfInfo, 32);
      const hmacKey = arrayBufferToHex(derivedKey);
      
      setState(prev => ({
        ...prev,
        validatorEcdhResult: result,
        validatorHmacKey: hmacKey
      }));
    } catch (error) {
      console.error('Validator ECDH failed:', error);
    }
  }, [state.validatorPrivateKey, state.dbPublicKey, state.hkdfSalt, state.hkdfInfo]);

  const validateJWS = useCallback(async () => {
    if (!state.validatorHmacKey || !state.jwt) return;
    
    try {
      const keyBytes = hexToArrayBuffer(state.validatorHmacKey);
      const secretKey = new Uint8Array(keyBytes);
      
      await jwtVerify(state.jwt, secretKey);
      setState(prev => ({ ...prev, validationResult: 'Signature Valid ✓ - JWS authenticity confirmed' }));
    } catch (error) {
      console.error('JWT validation failed:', error);
      setState(prev => ({ ...prev, validationResult: 'Signature Invalid ✗ - JWS verification failed' }));
    }
  }, [state.validatorHmacKey, state.jwt]);

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Fixed Reset Button */}
      <div className="fixed top-4 right-4 z-50">
        <Button
          onClick={resetAll}
          className="bg-red-600 hover:bg-red-700 text-white shadow-lg"
          data-testid="global-reset"
        >
          <RotateCcw className="mr-2 h-4 w-4" />
          Reset All
        </Button>
      </div>

      {/* Header with Problem and Solution */}
      <header className="bg-slate-900 text-white">
        <div className="container mx-auto px-6 py-12">
          <div className="max-w-4xl mx-auto">
            <h1 className="text-4xl font-bold mb-6">Single Show EC Key Proof of Possession with HSM</h1>
            
            <div className="grid md:grid-cols-2 gap-8">
              <Card className="bg-slate-800 border-slate-700">
                <CardContent className="p-6">
                  <h2 className="text-xl font-semibold mb-4 text-red-400 flex items-center">
                    <AlertTriangle className="mr-2" />
                    Problem
                  </h2>
                  <p className="text-slate-300 leading-relaxed">
                    Traditional key derivation exposes the master key to derive multiple HMAC keys, creating security vulnerabilities. 
                    Each derived key operation risks compromising the entire key hierarchy.
                  </p>
                </CardContent>
              </Card>
              
              <Card className="bg-slate-800 border-slate-700">
                <CardContent className="p-6">
                  <h2 className="text-xl font-semibold mb-4 text-emerald-400 flex items-center">
                    <Shield className="mr-2" />
                    Solution
                  </h2>
                  <p className="text-slate-300 leading-relaxed">
                    Use HSM-protected ECDH with blinding to derive multiple unrelated HMAC keys without exposing the master private key. 
                    This enables secure single show proof of possession.
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </header>

      {/* Actor Overview */}
      <section className="bg-white py-12 border-b border-slate-200">
        <div className="container mx-auto px-6">
          <div className="max-w-4xl mx-auto">
            <h2 className="text-3xl font-bold text-slate-900 mb-8 text-center">Actor Overview</h2>
            
            <div className="grid md:grid-cols-2 gap-8 mb-8">
              <Card className="bg-blue-50 border-blue-200">
                <CardContent className="p-6">
                  <div className="flex items-center mb-4">
                    <div className="bg-blue-500 text-white rounded-full w-12 h-12 flex items-center justify-center mr-4">
                      <Shield className="text-lg" />
                    </div>
                    <h3 className="text-xl font-semibold text-blue-900">JWS Producer</h3>
                  </div>
                  <div className="space-y-2 text-blue-800 mb-4">
                    <div className="flex items-center">
                      <span className="text-blue-500 mr-2">✓</span>
                      Generates a HSM protected long lived key pair d, [d]G
                    </div>
                    <div className="flex items-center">
                      <span className="text-blue-500 mr-2">✓</span>
                      Generates a blind b, which is a scalar suitable for the chosen curve
                    </div>
                    <div className="flex items-center">
                      <span className="text-blue-500 mr-2">✓</span>
                      Performs key blinding to generate blinded shared secret with ECDH
                    </div>
                    <div className="flex items-center">
                      <span className="text-blue-500 mr-2">✓</span>
                      Uses the single show HMAC key to produce the JWS
                    </div>
                  </div>
                </CardContent>
              </Card>
              
              <Card className="bg-teal-50 border-teal-200">
                <CardContent className="p-6">
                  <div className="flex items-center mb-4">
                    <div className="bg-teal-500 text-white rounded-full w-12 h-12 flex items-center justify-center mr-4">
                      <UserCheck className="text-lg" />
                    </div>
                    <h3 className="text-xl font-semibold text-teal-900">JWS Validator</h3>
                  </div>
                  <div className="space-y-2 text-teal-800 mb-4">
                    <div className="flex items-center">
                      <span className="text-teal-500 mr-2">✓</span>
                      Generates validation keypair v, [v]G and publishes public key V = [v]G
                    </div>
                    <div className="flex items-center">
                      <span className="text-teal-500 mr-2">✓</span>
                      Performs ECDH-HKDF to generate a single show (blinded) HMAC key
                    </div>
                    <div className="flex items-center">
                      <span className="text-teal-500 mr-2">✓</span>
                      Validates a JWS using the HMAC key
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Key Material Exchange Flow */}
            <Card className="bg-gray-50 border-gray-200">
              <CardContent className="p-6">
                <h3 className="text-xl font-semibold text-gray-900 mb-6 text-center">Key Material Exchange & Derivation</h3>
                
                <div className="flex flex-col items-center space-y-6">
                  <div className="flex items-center justify-between w-full max-w-2xl">
                    <div className="bg-teal-100 border-teal-300 border-2 rounded-lg p-3 text-center">
                      <div className="font-semibold text-teal-900">JWS Validator</div>
                      <div className="text-sm text-teal-700">V = [v]G</div>
                    </div>
                    
                    <div className="flex items-center">
                      <ArrowRight className="text-teal-500 mx-2" />
                      <div className="bg-teal-200 rounded px-2 py-1 text-xs text-teal-800">V</div>
                      <ArrowRight className="text-teal-500 mx-2" />
                    </div>
                    
                    <div className="bg-blue-100 border-blue-300 border-2 rounded-lg p-3 text-center">
                      <div className="font-semibold text-blue-900">JWS Producer</div>
                      <div className="text-sm text-blue-700">HSM + Server</div>
                    </div>
                  </div>

                  <div className="text-sm text-gray-600">1. JWS Validator sends public key V to JWS Producer</div>

                  <div className="flex items-center justify-between w-full max-w-2xl">
                    <div className="bg-blue-100 border-blue-300 border-2 rounded-lg p-3 text-center">
                      <div className="font-semibold text-blue-900">JWS Producer</div>
                      <div className="text-sm text-blue-700">Computes [db]G</div>
                    </div>
                    
                    <div className="flex items-center">
                      <ArrowRight className="text-blue-500 mx-2" />
                      <div className="bg-blue-200 rounded px-2 py-1 text-xs text-blue-800">[db]G</div>
                      <ArrowRight className="text-blue-500 mx-2" />
                    </div>
                    
                    <div className="bg-teal-100 border-teal-300 border-2 rounded-lg p-3 text-center">
                      <div className="font-semibold text-teal-900">JWS Validator</div>
                      <div className="text-sm text-teal-700">Receives [db]G</div>
                    </div>
                  </div>

                  <div className="text-sm text-gray-600">2. JWS Producer sends blinded EC key [db]G to JWS Validator</div>

                  <div className="bg-yellow-100 border-yellow-300 border-2 rounded-lg p-4 text-center max-w-xl">
                    <div className="font-semibold text-yellow-900 mb-2">3. Both actors derive the same blinded single show HMAC key</div>
                    <div className="text-sm text-yellow-800">Using ECDH and HKDF operations</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Interactive Demo Steps */}
      <main className="py-12">
        <div className="container mx-auto px-6">
          <div className="max-w-4xl mx-auto space-y-12">
            <h2 className="text-3xl font-bold text-slate-900 text-center">Interactive Demonstration</h2>
            
            {/* Step 1: Generate EC Key Pairs */}
            <StepCard
              stepNumber={1}
              stepColor="green"
              title="Generate EC Key Pairs"
              explanation={
                <div>
                  <h4 className="font-semibold mb-2">Setup Stage</h4>
                  <p className="mb-3">
                    Generate elliptic curve key pairs on secp256r1 curve. The JWS Producer uses an HSM to protect its private key 'd', 
                    while the JWS Validator generates a standard key pair where [v]G means scalar multiplication between private scalar 'v' and generator point 'G'.
                  </p>
                  <div className="grid md:grid-cols-2 gap-4">
                    <Alert className="bg-green-100 border-green-300">
                      <AlertDescription className="text-green-800">
                        <strong>JWS Validator:</strong> Generates v, [v]G where v is private scalar and [v]G is the public key point.
                      </AlertDescription>
                    </Alert>
                    <Alert className="bg-green-100 border-green-300">
                      <AlertDescription className="text-green-800">
                        <strong>HSM (JWS Producer):</strong> Private key 'd' never exposed but shown here for demo purposes only.
                      </AlertDescription>
                    </Alert>
                  </div>
                </div>
              }
              onAction={generateKeys}
              actionLabel="Generate New Key Pairs"
              actionIcon={<RefreshCw className="mr-2 h-4 w-4" />}
            >
              <div className="grid md:grid-cols-2 gap-6">
                {/* JWS Validator Keys */}
                <Card className="bg-white border-green-200">
                  <CardContent className="p-4">
                    <h4 className="font-semibold text-green-900 mb-3 flex items-center">
                      <UserCheck className="mr-2" />
                      JWS Validator
                    </h4>
                    
                    <div className="space-y-4">
                      <CryptoInput
                        label="Private Key (v)"
                        value={state.validatorPrivateKey}
                        testId="validator-private-key"
                      />
                      <CryptoInput
                        label="Public Key X-coordinate ([v]G.x)"
                        value={state.validatorPublicKey.x}
                        testId="validator-public-key-x"
                      />
                      <CryptoInput
                        label="Public Key Y-coordinate ([v]G.y)"
                        value={state.validatorPublicKey.y}
                        testId="validator-public-key-y"
                      />
                    </div>
                  </CardContent>
                </Card>

                {/* HSM Keys */}
                <Card className="bg-white border-green-200">
                  <CardContent className="p-4">
                    <h4 className="font-semibold text-green-900 mb-3 flex items-center">
                      <Cpu className="mr-2" />
                      JWS Producer (HSM Protected)
                    </h4>
                    
                    <div className="space-y-4">
                      <div>
                        <div className="flex gap-2 items-end">
                          <div className="flex-1">
                            <CryptoInput
                              label="HSM Private Key (d)"
                              value={state.hsmKeyRevealed ? state.hsmPrivateKey : (state.hsmPrivateKey ? '••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••' : '')}
                              testId="hsm-private-key"
                              copyable={state.hsmKeyRevealed && !!state.hsmPrivateKey}
                            />
                          </div>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={toggleHSMKeyVisibility}
                            className="bg-amber-500 text-white hover:bg-amber-600"
                            data-testid="toggle-hsm-key"
                            disabled={!state.hsmPrivateKey}
                          >
                            {state.hsmKeyRevealed ? <EyeOff className="h-4 w-4 mr-1" /> : <Eye className="h-4 w-4 mr-1" />}
                            {state.hsmKeyRevealed ? 'Hide' : 'Reveal'}
                          </Button>
                        </div>
                        <p className="text-xs text-amber-600 mt-1">⚠️ Demo only - HSM keys are never exposed in production</p>
                      </div>
                      
                      <CryptoInput
                        label="HSM Public Key X-coordinate ([d]G.x)"
                        value={state.hsmPublicKey.x}
                        testId="hsm-public-key-x"
                      />
                      <CryptoInput
                        label="HSM Public Key Y-coordinate ([d]G.y)"
                        value={state.hsmPublicKey.y}
                        testId="hsm-public-key-y"
                      />
                    </div>
                  </CardContent>
                </Card>
              </div>
            </StepCard>

            {/* Step 2: Generate Blind and Apply Blinding */}
            <StepCard
              stepNumber={2}
              stepColor="blue"
              title="Generate Blind and Apply Blinding"
              explanation={
                <div>
                  <h4 className="font-semibold mb-2">Why Blinding is Essential</h4>
                  <p className="mb-3">
                    Blinding enables deriving multiple unrelated HMAC keys from a single HSM-protected private key without compromising security. 
                    The blind generator (which can be the user device, attestation issuer, or JWS Producer server) creates a random scalar 'b'. 
                    For this demo, we use the JWS Producer server.
                  </p>
                  <p className="mb-3">
                    Applying the blind to the JWS Validator public key may seem odd, but scalar multiplication is commutative. 
                    It's better for the HSM to apply private key 'd' to a specific blinded validator value rather than letting the server choose the validator.
                  </p>
                </div>
              }
            >
              <div className="grid md:grid-cols-2 gap-6">
                <Card className="bg-white border-blue-200">
                  <CardContent className="p-4">
                    <h4 className="font-semibold text-blue-900 mb-3">Random Blind Generation</h4>
                    <CryptoInput
                      label="Blind Value (b)"
                      value={state.blind}
                      testId="blind-value"
                    />
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={generateBlind}
                      className="mt-3 bg-blue-500 text-white hover:bg-blue-600"
                      data-testid="generate-blind"
                      disabled={!state.validatorPublicKey.x}
                    >
                      <Dice1 className="mr-2 h-4 w-4" />
                      Generate & Apply Blind
                    </Button>
                    {!state.validatorPublicKey.x && (
                      <p className="text-xs text-blue-600 mt-1">⚠️ Generate keys in Step 1 first</p>
                    )}
                  </CardContent>
                </Card>
                
                <Card className="bg-white border-blue-200">
                  <CardContent className="p-4">
                    <h4 className="font-semibold text-blue-900 mb-3">Blinded Validator Public Key</h4>
                    <CryptoInput
                      label="Result X ([bv]G.x)"
                      value={state.blindedValidatorPublicKey.x}
                      testId="blinded-public-key-x"
                    />
                    <CryptoInput
                      label="Result Y ([bv]G.y)"
                      value={state.blindedValidatorPublicKey.y}
                      testId="blinded-public-key-y"
                    />
                    
                    {state.blind && state.blindedValidatorPublicKey.x && (
                      <Alert className="bg-blue-100 border-blue-300 mt-3">
                        <Calculator className="h-4 w-4" />
                        <AlertDescription className="text-blue-700">
                          <strong>Math Operation:</strong> b × [v]G = [bv]G<br/>
                          The blind scalar 'b' is multiplied with the validator's public key point [v]G
                        </AlertDescription>
                      </Alert>
                    )}
                  </CardContent>
                </Card>
              </div>
              
              {/* Generate [db]G Section */}
              {state.blind && state.hsmPrivateKey && (
                <Card className="bg-white border-blue-200 mt-6">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between mb-4">
                      <h4 className="font-semibold text-blue-900">Generate [db]G for Validator</h4>
                      <Button
                        onClick={generateDbG}
                        className="bg-blue-600 hover:bg-blue-700 text-white"
                        data-testid="generate-dbg"
                      >
                        <Key className="mr-2 h-4 w-4" />
                        Generate [db]G
                      </Button>
                    </div>
                    
                    <div className="grid md:grid-cols-2 gap-4">
                      <CryptoInput
                        label="Public Key X [db]G.x for Validator"
                        value={state.dbPublicKey.x}
                        testId="db-public-key-x"
                      />
                      <CryptoInput
                        label="Public Key Y [db]G.y for Validator"
                        value={state.dbPublicKey.y}
                        testId="db-public-key-y"
                      />
                    </div>
                    
                    <Alert className="bg-blue-100 border-blue-300 mt-4">
                      <Info className="h-4 w-4" />
                      <AlertDescription className="text-blue-700">
                        <strong>Value Computation:</strong> [db]G is computed from fixed HSM private key d and blind b. This value is deterministic and can be calculated by the JWS Producer (as shown) or by an attestation issuer who knows the HSM public key and generates the blind b.
                      </AlertDescription>
                    </Alert>
                    
                    <Alert className="bg-blue-100 border-blue-300 mt-3">
                      <Info className="h-4 w-4" />
                      <AlertDescription className="text-blue-700">
                        <strong>Validator Communication:</strong> These public key values can be sent to the validator using a JWT when using "PKDS" (Public Key Distribution Service) or transmitted out-of-band through secure channels.
                      </AlertDescription>
                    </Alert>
                  </CardContent>
                </Card>
              )}
            </StepCard>

            {/* Step 3: HSM ECDH Operation */}
            <StepCard
              stepNumber={3}
              stepColor="red"
              title="Create Single Use EC Key with HSM"
              explanation={
                <div>
                  <h4 className="font-semibold mb-2">HSM ECDH Computation</h4>
                  <p>
                    The HSM performs ECDH(d, [bv]G) to compute the blinded shared secret [dbv]G. 
                    The private key 'd' never leaves the HSM, ensuring maximum security. This creates the single use EC key that incorporates both the blind and HSM protected secret.
                  </p>
                </div>
              }
              onAction={performHSMECDH}
              actionLabel="Execute HSM ECDH Operation"
              actionIcon={<Cpu className="mr-2 h-4 w-4" />}
            >
              <Card className="bg-white border-red-200">
                <CardContent className="p-4">
                  <h4 className="font-semibold text-red-900 mb-3 flex items-center">
                    <Cpu className="mr-2" />
                    HSM ECDH: d × [bv]G = [dbv]G
                  </h4>
                  
                  <div className="grid md:grid-cols-2 gap-4">
                    <div>
                      <CryptoInput
                        label="Input X: [bv]G.x (from Step 2)"
                        value={state.blindedValidatorPublicKey.x}
                        testId="ecdh-input-x"
                      />
                      <CryptoInput
                        label="Input Y: [bv]G.y (from Step 2)"
                        value={state.blindedValidatorPublicKey.y}
                        testId="ecdh-input-y"
                      />
                    </div>
                    
                    <div>
                      <CryptoInput
                        label="Output X: [dbv]G.x (Blinded Shared Secret)"
                        value={state.hsmEcdhResult.x}
                        testId="ecdh-output-x"
                      />
                      <CryptoInput
                        label="Output Y: [dbv]G.y (normally discarded)"
                        value={state.hsmEcdhResult.y}
                        testId="ecdh-output-y"
                      />
                    </div>
                  </div>
                  
                  {state.hsmEcdhResult.x && (
                    <Alert className="bg-red-100 border-red-300 mt-4">
                      <Cpu className="h-4 w-4" />
                      <AlertDescription className="text-red-700">
                        <strong>Math Operation:</strong> d × [bv]G = [dbv]G<br/>
                        The HSM private key 'd' is multiplied with the blinded validator public key point [bv]G
                      </AlertDescription>
                    </Alert>
                  )}
                </CardContent>
              </Card>
            </StepCard>

            {/* Step 4: HKDF Key Derivation */}
            <StepCard
              stepNumber={4}
              stepColor="purple"
              title="Derive HMAC Key with HKDF"
              explanation={
                <div>
                  <h4 className="font-semibold mb-2">HKDF Key Derivation</h4>
                  <p>
                    The blinded shared secret from Step 3 serves as Input Key Material (IKM) for HKDF. 
                    HKDF performs extract and expand operations to derive a secure HMAC key. We use the x-coordinate of [dbv]G as IKM to connect the two steps.
                  </p>
                </div>
              }
              onAction={deriveHMACKey}
              actionLabel="Derive HMAC Key with HKDF"
              actionIcon={<Key className="mr-2 h-4 w-4" />}
            >
              <Card className="bg-white border-purple-200">
                <CardContent className="p-4">
                  <h4 className="font-semibold text-purple-900 mb-3">HKDF-SHA256 Parameters</h4>
                  
                  <div className="space-y-4">
                    <CryptoInput
                      label="IKM (Input Key Material): [dbv]G.x"
                      value={state.hsmEcdhResult.x}
                      testId="hkdf-ikm"
                    />
                    
                    <div className="grid md:grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label className="text-sm font-medium">Salt (optional)</Label>
                        <Input
                          value={state.hkdfSalt}
                          onChange={(e) => updateHkdfSalt(e.target.value)}
                          placeholder="Leave empty for null salt"
                          className="font-mono text-xs"
                          data-testid="hkdf-salt-input"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label className="text-sm font-medium">Info (context string)</Label>
                        <Input
                          value={state.hkdfInfo}
                          onChange={(e) => updateHkdfInfo(e.target.value)}
                          placeholder="Context information"
                          className="font-mono text-xs"
                          data-testid="hkdf-info-input"
                        />
                      </div>
                    </div>
                    
                    <CryptoInput
                      label="Derived HMAC Key (256-bit)"
                      value={state.hmacKey}
                      testId="derived-hmac-key"
                    />
                    
                    {state.hkdfPrk && (
                      <div className="border-t pt-4 mt-4">
                        <h5 className="font-semibold text-purple-900 mb-3">HKDF Process Details</h5>
                        <CryptoInput
                          label="PRK (Pseudo-Random Key) from Extract Phase"
                          value={state.hkdfPrk}
                          testId="hkdf-prk"
                          copyable={false}
                        />
                        
                        <Alert className="bg-purple-100 border-purple-300 mt-3">
                          <Key className="h-4 w-4" />
                          <AlertDescription className="text-purple-700">
                            <strong>Extract Phase:</strong> PRK = HMAC-SHA256(Salt, IKM)<br/>
                            <strong>Expand Phase:</strong> OKM = HMAC-SHA256(PRK, Info) (32 bytes default length)<br/>
                            <em>Demo uses standard 256-bit (32 byte) output length for HS256 compatibility</em>
                          </AlertDescription>
                        </Alert>
                      </div>
                    )}
                  </div>
                  
                  <Alert className="bg-purple-100 border-purple-300 mt-4">
                    <AlertDescription className="text-purple-700">
                      <strong>HKDF Process:</strong> Extract(salt, ikm) → PRK → Expand(prk, info, length) → HMAC Key
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>
            </StepCard>

            {/* Step 5: Sign JWT */}
            <StepCard
              stepNumber={5}
              stepColor="orange"
              title="Sign JWT with HMAC Key"
              onAction={signJWT}
              actionLabel="Sign JWT"
              actionIcon={<FileSignature className="mr-2 h-4 w-4" />}
            >
              <Card className="bg-white border-orange-200">
                <CardContent className="p-4">
                  <h4 className="font-semibold text-orange-900 mb-3">JWT Creation (HS256)</h4>
                  
                  <div className="space-y-3">
                    <CryptoInput
                      label="HMAC Key (from Step 4)"
                      value={state.hmacKey}
                      testId="jwt-hmac-key"
                    />
                    
                    <div className="space-y-2">
                      <Label className="text-sm font-medium">JWT Payload (editable)</Label>
                      <textarea
                        value={state.jwtPayload}
                        onChange={(e) => updateJwtPayload(e.target.value)}
                        className="w-full font-mono text-xs border rounded px-3 py-2 bg-background resize-none"
                        rows={4}
                        placeholder="JSON payload for JWT"
                        data-testid="jwt-payload-input"
                      />
                    </div>
                    
                    <CryptoInput
                      label="Complete JWS"
                      value={state.jwt}
                      multiline
                      testId="complete-jws"
                    />
                  </div>
                  
                  <Alert className="bg-orange-100 border-orange-300 mt-4">
                    <FileSignature className="h-4 w-4" />
                    <AlertDescription className="text-orange-700">
                      <strong>JWT Signing:</strong> The HMAC key derived from the blinded shared secret is used to sign the JWT payload using HS256 algorithm. The resulting JWS can be verified by the validator using their own derived HMAC key.
                    </AlertDescription>
                  </Alert>
                </CardContent>
              </Card>
            </StepCard>

            {/* Step 6: Validator ECDH and Validation */}
            <StepCard
              stepNumber={6}
              stepColor="teal"
              title="Validator ECDH and JWS Validation"
              explanation={
                <div>
                  <h4 className="font-semibold mb-2">Reconstruct and Validate</h4>
                  <p>
                    The JWS Validator performs ECDH(v, [db]G) to generate the same blinded shared secret [dbv]G, 
                    enabling derivation of the identical HMAC key for signature verification. Then validates the JWS.
                  </p>
                </div>
              }
            >
              <div className="space-y-6">
                <Card className="bg-white border-teal-200">
                  <CardContent className="p-4">
                    <h4 className="font-semibold text-teal-900 mb-3 flex items-center">
                      <Calculator className="mr-2" />
                      Validator ECDH: v × [db]G = [vdb]G = [dbv]G
                    </h4>
                    
                    <div className="grid md:grid-cols-2 gap-4 mb-4">
                      <div>
                        <CryptoInput
                          label="Input X: [db]G.x (from JWS Producer)"
                          value={state.dbPublicKey.x}
                          testId="validator-ecdh-input-x"
                        />
                        <CryptoInput
                          label="Input Y: [db]G.y (from JWS Producer)"
                          value={state.dbPublicKey.y}
                          testId="validator-ecdh-input-y"
                        />
                      </div>
                      
                      <div>
                        <CryptoInput
                          label="Output X: [vdb]G.x = [dbv]G.x"
                          value={state.validatorEcdhResult.x}
                          testId="validator-ecdh-output-x"
                        />
                        <CryptoInput
                          label="Derived HMAC Key (should match Step 4)"
                          value={state.validatorHmacKey}
                          testId="validator-hmac-key"
                        />
                      </div>
                    </div>
                    
                    <Button
                      onClick={performValidatorECDH}
                      className="bg-teal-500 hover:bg-teal-600 text-white"
                      data-testid="perform-validator-ecdh"
                      disabled={!state.dbPublicKey.x || !state.validatorPrivateKey}
                    >
                      <Calculator className="mr-2 h-4 w-4" />
                      Perform Validator ECDH & HKDF
                    </Button>
                  </CardContent>
                </Card>

                <Card className="bg-white border-teal-200">
                  <CardContent className="p-4">
                    <h4 className="font-semibold text-teal-900 mb-3">JWS Validation</h4>
                    
                    <div className="space-y-4">
                      <CryptoInput
                        label="JWS to Validate (auto-filled from Step 5)"
                        value={state.jwt}
                        multiline
                        testId="validation-jws"
                      />
                      
                      <div className="flex items-center justify-between">
                        <Button
                          onClick={validateJWS}
                          className="bg-teal-500 hover:bg-teal-600 text-white"
                          data-testid="validate-jws"
                          disabled={!state.validatorHmacKey || !state.jwt}
                        >
                          <CheckCircle2 className="mr-2 h-4 w-4" />
                          Validate JWS Signature
                        </Button>
                        
                        {state.validationResult && (
                          <div className={`px-4 py-2 rounded-lg font-medium ${
                            state.validationResult.includes('Valid') 
                              ? 'bg-green-100 text-green-800 border border-green-200' 
                              : 'bg-red-100 text-red-800 border border-red-200'
                          }`}>
                            {state.validationResult}
                          </div>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </StepCard>
          </div>
        </div>
      </main>
    </div>
  );
}