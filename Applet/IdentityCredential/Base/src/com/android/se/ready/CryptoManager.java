package com.android.se.ready;

import static com.android.se.ready.ICConstants.LONG_SIZE;
import static com.android.se.ready.ICConstants.SHORT_SIZE;
import static com.android.se.ready.ICConstants.X509_CERT_BASE;
import static com.android.se.ready.ICConstants.X509_CERT_POS_TOTAL_LEN;
import static com.android.se.ready.ICConstants.X509_CERT_POS_VALID_NOT_AFTER;
import static com.android.se.ready.ICConstants.X509_CERT_POS_VALID_NOT_BEFORE;
import static com.android.se.ready.ICConstants.X509_DER_POB;
import static com.android.se.ready.ICConstants.X509_DER_SIGNATURE;

import com.android.javacard.keymaster.KMAppletBridge;

import javacard.framework.AID;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

public class CryptoManager {

    public static final byte FLAG_TEST_CREDENTIAL = 0;
    public static final byte FLAG_PROVISIONING_INITIALIZED = 1;
    public static final byte FLAG_PROVISIONING_KEYS_INITIALIZED = 2;
    public static final byte FLAG_PROVISIONING_CREDENTIAL_STATE = 3;
    public static final byte FLAG_PERSONALIZING_ENTRIES = 4;
    public static final byte FLAG_PERSONALIZING_FINISH_ENTRIES = 5;
    public static final byte FLAG_PERSONALIZING_FINISH_ENTRIES_VALUES = 6;
    public static final byte FLAG_PERSONALIZING_FINISH_ADDING_ENTRIES = 7;
    public static final byte FLAG_PERSONALIZING_FINISH_GET_CREDENTIAL = 8;
    public static final byte FLAG_PRESENTING_CREATE_EPHEMERAL = 9;
    public static final byte FLAG_PRESENTING_CREATE_AUTH_CHALLENGE = 0x0A;
    public static final byte FLAG_PRESENTING_START_RETRIEVAL = 0x0B;
    public static final byte FLAG_PRESENTING_START_RETRIEVE_ENTRY = 0x0C;
    public static final byte FLAG_UPDATE_CREDENTIAL = 0x0D;
    public static final byte FLAG_HMAC_INITIALIZED = 0x0E;
    private static final byte STATUS_FLAGS_SIZE = 2;

    // Actual Crypto implementation
    private final ICryptoProvider mCryptoProvider;
    
    // Hardware bound key, initialized during Applet installation
    private final byte[] mHBK;
    
    // Storage key for a credential
    private final byte[] mCredentialStorageKey;

    // KeyPair for credential key
    private final byte[] mCredentialKeyPair;
    // Temporary buffer in memory for keyLengths
    private final short[] mCredentialKeyPairLengths;

    // Signature object for creating and verifying credential signatures 
    MessageDigest mDigest;
    // Digester object for calculating proof of provisioning data digest
    final MessageDigest mSecondaryDigest;
    // Digester object for calculating addition data digest
    final MessageDigest mAdditionalDataDigester;

    // Random data generator 
    private final RandomData mRandomData;

    // Temporary buffer in memory for status flags
    private final byte[] mStatusFlags;

    public CryptoManager(ICryptoProvider cryptoProvider) {
    	mCryptoProvider = cryptoProvider;
    	
        //mTempBuffer = JCSystem.makeTransientByteArray((short) (TEMP_BUFFER_SIZE + AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE),
        //        JCSystem.CLEAR_ON_DESELECT);
    	//mTempBuffer = KMRepository.instance().getHeap();

        mStatusFlags = JCSystem.makeTransientByteArray((short)(STATUS_FLAGS_SIZE), JCSystem.CLEAR_ON_DESELECT);

        // Secure Random number generation for HBK
        mRandomData = RandomData.getInstance(RandomData.ALG_TRNG);
        mHBK = new byte[ICConstants.AES_GCM_KEY_SIZE];
        mRandomData.nextBytes(mHBK, (short)0, ICConstants.AES_GCM_KEY_SIZE);

        // Create the storage key byte array 
        mCredentialStorageKey = JCSystem.makeTransientByteArray(ICConstants.AES_GCM_KEY_SIZE, JCSystem.CLEAR_ON_RESET);
        mCredentialKeyPair = JCSystem.makeTransientByteArray((short)(ICConstants.EC_KEY_SIZE * 3 + 1), JCSystem.CLEAR_ON_RESET);
        mCredentialKeyPairLengths = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_RESET);

        try {
            //External access is enabled to pass VTS, after some VTS passed, remaining VTS failed while MessageDigest update if it is not exported.
            mDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, true);
        } catch (CryptoException e) {
            //External access is not supported in JCard simulator.
            mDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        }
        mSecondaryDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        mAdditionalDataDigester = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

    }

    /**
     * Reset the internal state. Resets the credential private key, the storage key
     * as well as all status flags.
     */
    public void reset() {
        Util.arrayFillNonAtomic(mStatusFlags, (short)0, STATUS_FLAGS_SIZE, (byte)0);
        Util.arrayFillNonAtomic(mCredentialStorageKey, (short)0, KeyBuilder.LENGTH_AES_128, (byte)0);
    }
    
    /**
     * Returns the used AES key size for the storage as well as hardware-bound key
     * in bit.
     */
    public static short getAESKeySize() {
        return (short) (ICConstants.AES_GCM_KEY_SIZE * 8);
    }
    
    void createCredentialStorageKey(boolean testCredential) {
        // Check if it is a test credential
        if(testCredential) { // Test credential
        	Util.arrayFillNonAtomic(mCredentialStorageKey, (short) 0, ICConstants.AES_GCM_KEY_SIZE, (byte)0x00);
        } else {
	        // Generate the AES-128 storage key 
	        generateRandomData(mCredentialStorageKey, (short) 0, ICConstants.AES_GCM_KEY_SIZE);
        }
    }
    
    short getCredentialStorageKey(byte[] storageKey, short skStart) {
        if(storageKey != null) {
            Util.arrayCopyNonAtomic(mCredentialStorageKey, (short) 0, storageKey, skStart, ICConstants.AES_GCM_KEY_SIZE);
        }
        return ICConstants.AES_GCM_KEY_SIZE;
    }

    short setCredentialStorageKey(byte[] storageKey, short skStart) {
        if(storageKey != null) {
            Util.arrayCopyNonAtomic(storageKey, skStart, mCredentialStorageKey, (short) 0, ICConstants.AES_GCM_KEY_SIZE);
        }
        return ICConstants.AES_GCM_KEY_SIZE;
    }

    void createEcKeyPair(byte[] keyPairBlob, short keyBlobStart, short[] keyPairLengths) {
        mCryptoProvider.createECKey(keyPairBlob, keyBlobStart, ICConstants.EC_KEY_SIZE, keyPairBlob, (short)(keyBlobStart + ICConstants.EC_KEY_SIZE), (short) (ICConstants.EC_KEY_SIZE * 2 + 1), keyPairLengths);
    }

    short createEcKeyPairAndAttestation(boolean isTestCredential,
    		byte[] argsBuff,
    		short challengeOffset, short challengeLen,
    		short appIdOffset, short appIdLen,
    		short nowMsOffset, short nowMsLen,
    		short expireTimeOffset, short expireTimeLen,
    		byte[] scratchPad, short scratchPadOffset) {
        createEcKeyPair(mCredentialKeyPair, (short)0, mCredentialKeyPairLengths);

        short pubKeyOffset = scratchPadOffset;
        short pubKeyLen = getCredentialEcPubKey(scratchPad, pubKeyOffset);
        short certLen = (short)0;
		AID keymasterAID = JCSystem.lookupAID(ICConstants.KEYMASTER_AID, (byte)0, (byte)ICConstants.KEYMASTER_AID.length);
		if(keymasterAID == null) {
			ISOException.throwIt((short)1);;
		}
		
		byte[] globalArgsArray = (byte[])JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, ICConstants.TEMP_BUFFER_SIZE);
		Util.arrayCopyNonAtomic(argsBuff, challengeOffset, globalArgsArray, challengeOffset, challengeLen);
		Util.arrayCopyNonAtomic(argsBuff, appIdOffset, globalArgsArray, appIdOffset, appIdLen);
		Util.arrayCopyNonAtomic(argsBuff, nowMsOffset, globalArgsArray, nowMsOffset, nowMsLen);
		Util.arrayCopyNonAtomic(argsBuff, expireTimeOffset, globalArgsArray, expireTimeOffset, expireTimeLen);
		Util.arrayCopyNonAtomic(scratchPad, pubKeyOffset, globalArgsArray, (short)(expireTimeOffset + expireTimeLen), pubKeyLen);
		Shareable sharable = JCSystem.getAppletShareableInterfaceObject(keymasterAID, (byte)1);
        certLen = ((KMAppletBridge)sharable).createAttestationForEcPublicKey(isTestCredential,
        			globalArgsArray, (short)(expireTimeOffset + expireTimeLen), pubKeyLen,
        			appIdOffset, appIdLen,
        			challengeOffset, challengeLen,
        			nowMsOffset, (short)ICConstants.LONG_SIZE,
        			expireTimeOffset, (short)ICConstants.LONG_SIZE,
        			globalArgsArray, (short)0);
        Util.arrayCopyNonAtomic(globalArgsArray, (short)0, scratchPad, scratchPadOffset, certLen);
		return certLen;
    }
    
    short getCredentialEcKey(byte[] credentialEcKey, short start) {
        if(credentialEcKey != null) {
            Util.arrayCopyNonAtomic(mCredentialKeyPair, (short) 0, credentialEcKey, start, mCredentialKeyPairLengths[0]);
        }
    	return mCredentialKeyPairLengths[0];
    }

    short setCredentialEcKey(byte[] credentialEcKey, short start) {
        if(credentialEcKey != null) {
            Util.arrayCopyNonAtomic(credentialEcKey, start, mCredentialKeyPair, (short) 0, ICConstants.EC_KEY_SIZE);
            mCredentialKeyPairLengths[0] = ICConstants.EC_KEY_SIZE;
        }
        return ICConstants.EC_KEY_SIZE;
    }

    short getCredentialEcPubKey(byte[] credentialEcPubKey, short start) {
        if(credentialEcPubKey != null) {
            Util.arrayCopyNonAtomic(mCredentialKeyPair, mCredentialKeyPairLengths[0], credentialEcPubKey, start, mCredentialKeyPairLengths[1]);
        }
        return mCredentialKeyPairLengths[1];
    }

    short ecSignWithNoDigest(byte[] sha256Hash, short hashOffset, byte[] signBuff, short signBuffOffset) {
    	return mCryptoProvider.ecSignWithNoDigest(mCredentialKeyPair, (short)0, mCredentialKeyPairLengths[0],//Private key
                sha256Hash, hashOffset, ICConstants.SHA256_DIGEST_SIZE, signBuff, signBuffOffset);
    }

    short ecSignWithSHA256Digest(byte[] data, short dataOffset, short dataLen, byte[] signBuff, short signBuffOffset) {
        return mCryptoProvider.ecSignWithSHA256Digest(
                mCredentialKeyPair, (short)0, mCredentialKeyPairLengths[0],//Private key
                data, dataOffset, dataLen, signBuff, signBuffOffset);
    }

    boolean ecVerifyWithNoDigest(byte[] pubKey, short pubKeyOffset, short pubKeyLen,
                                 byte[] data, short dataOffset, short dataLen,
                                 byte[] signBuff, short signBuffOffset, short signLength) {
        return mCryptoProvider.ecVerifyWithNoDigest(pubKey, pubKeyOffset, pubKeyLen, data, dataOffset, dataLen, signBuff, signBuffOffset, signLength);
    }

    void setStatusFlag(byte flag, boolean isSet) {
    	ICUtil.setBit(mStatusFlags, flag, isSet);
    }
    

    boolean getStatusFlag(byte flag) {
    	return ICUtil.getBit(mStatusFlags, flag);
    }
    
    void generateRandomData(byte[] tempBuffer, short offset, short length) {
        mRandomData.nextBytes(tempBuffer, offset, length);
    }

    public void assertStatusFlagSet(byte statusFlag) {
        if (!ICUtil.getBit(mStatusFlags, statusFlag)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
    
    public void assertCredentialInitialized() {
        assertStatusFlagSet(FLAG_PROVISIONING_INITIALIZED);
    }

    public void assertInPersonalizationState() {
        assertStatusFlagSet(FLAG_PROVISIONING_CREDENTIAL_STATE);
    }

    public void assertStatusFlagNotSet(byte statusFlag) {
        if (ICUtil.getBit(mStatusFlags, statusFlag)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
    }
    
    public short aesGCMEncrypt(byte[] data, short dataOffset, short dataLen,
    		byte[] outData, short outDataOffset,
    		byte[] authData, short authDataOffset, short authDataLen,
    		byte[] outNonceAndTag, short outNonceAndTagOff) {

        // Generate the IV
        mRandomData.nextBytes(outNonceAndTag, outNonceAndTagOff, ICConstants.AES_GCM_IV_SIZE);
    	return mCryptoProvider.aesGCMEncrypt(mCredentialStorageKey, (short)0, (short)mCredentialStorageKey.length,
    			data, dataOffset, dataLen,
    			outData, outDataOffset,
    			outNonceAndTag, (short)outNonceAndTagOff, ICConstants.AES_GCM_IV_SIZE,
    			authData, authDataOffset, authDataLen,
    			outNonceAndTag, (short)(outNonceAndTagOff + ICConstants.AES_GCM_IV_SIZE), ICConstants.AES_GCM_TAG_SIZE);
    }

    public boolean aesGCMDecrypt(byte[] encData, short encDataOffset, short encDataLen,
                               byte[] outData, short outDataOffset,
                               byte[] authData, short authDataOffset, short authDataLen,
                               byte[] nonceAndTag, short nonceAndTagOff) {

        return mCryptoProvider.aesGCMDecrypt(mCredentialStorageKey, (short)0, (short)mCredentialStorageKey.length,
                encData, encDataOffset, encDataLen,
                outData, outDataOffset,
                nonceAndTag, nonceAndTagOff, ICConstants.AES_GCM_IV_SIZE,
                authData, authDataOffset, authDataLen,
                nonceAndTag, (short)(nonceAndTagOff + ICConstants.AES_GCM_IV_SIZE), ICConstants.AES_GCM_TAG_SIZE);
    }

    short entryptCredentialData(boolean isTestCredential,
    		byte[] data, short dataOffset, short dataLen,
    		byte[] outData, short outDataOffset,
    		byte[] authData, short authDataOffset, short authDataLen,
    		byte[] outNonceAndTag, short outNonceAndTagOff) {

        // Generate the IV
        mRandomData.nextBytes(outNonceAndTag, outNonceAndTagOff, ICConstants.AES_GCM_IV_SIZE);
        if(isTestCredential) {
        	//In case of testCredential HBK should be initialized with 0's
        	//If testCredential is true mCredentialStorageKey is already initialized with 0's so no need to create separate HBK for testCredential.
        	return mCryptoProvider.aesGCMEncrypt(mCredentialStorageKey, (short)0, (short)mCredentialStorageKey.length,
	    			data, dataOffset, dataLen,
	    			outData, outDataOffset,
	    			outNonceAndTag, (short)outNonceAndTagOff, ICConstants.AES_GCM_IV_SIZE,
	    			authData, authDataOffset, authDataLen,
	    			outNonceAndTag, (short)(outNonceAndTagOff + ICConstants.AES_GCM_IV_SIZE), ICConstants.AES_GCM_TAG_SIZE);
        } else {
	    	return mCryptoProvider.aesGCMEncrypt(mHBK, (short)0, (short)mHBK.length,
	    			data, dataOffset, dataLen,
	    			outData, outDataOffset,
	    			outNonceAndTag, (short)outNonceAndTagOff, ICConstants.AES_GCM_IV_SIZE,
	    			authData, authDataOffset, authDataLen,
	    			outNonceAndTag, (short)(outNonceAndTagOff + ICConstants.AES_GCM_IV_SIZE), ICConstants.AES_GCM_TAG_SIZE);
        }
    }

    boolean decryptCredentialData(boolean isTestCredential, byte[] encryptedCredentialKeyBlob, short keyBlobOff, short keyBlobSize,
                                            byte[] outData, short outDataOffset,
                                            byte[] nonce, short nonceOffset, short nonceLen,
                                            byte[] authData, short authDataOffset, short authDataLen,
                                            byte[] authTag, short authTagOffset, short authTagLen) {

        if(isTestCredential) {
            //In case of testCredential HBK should be initialized with 0's
            //If testCredential is true mCredentialStorageKey is already initialized with 0's so no need to create separate HBK for testCredential.
            return mCryptoProvider.aesGCMDecrypt(mCredentialStorageKey, (short)0, (short)mCredentialStorageKey.length,
                    encryptedCredentialKeyBlob, keyBlobOff, keyBlobSize,
                    outData, outDataOffset,
                    nonce, nonceOffset, nonceLen,
                    authData, authDataOffset, authDataLen,
                    authTag, authTagOffset, authTagLen);
        } else {
            return mCryptoProvider.aesGCMDecrypt(mHBK, (short)0, (short)mHBK.length,
                    encryptedCredentialKeyBlob, keyBlobOff, keyBlobSize,
                    outData, outDataOffset,
                    nonce, nonceOffset, nonceLen,
                    authData, authDataOffset, authDataLen,
                    authTag, authTagOffset, authTagLen);
        }
    }

    public short createECDHSecret(byte[] privKey, short privKeyOffset, short privKeyLen,
                                  byte[] pubKey, short pubKeyOffset, short pubKeyLen,
                                  byte[] outSecret, short outSecretOffset) {
        return mCryptoProvider.createECDHSecret(privKey, privKeyOffset, privKeyLen,
                pubKey, pubKeyOffset, pubKeyLen,
                outSecret, outSecretOffset);
    }

    public short hkdf(byte[] sharedSecret, short sharedSecretOffset, short sharedSecretLen,
                      byte[] salt, short saltOffset, short saltLen,
                      byte[] info, short infoOffset, short infoLen,
                      byte[] outDerivedKey, short outDerivedKeyOffset, short expectedKeySize) {
        return mCryptoProvider.hkdf(sharedSecret, sharedSecretOffset, sharedSecretLen,
                                    salt, saltOffset, saltLen,
                                    info, infoOffset, infoLen,
                                    outDerivedKey, outDerivedKeyOffset, expectedKeySize);
    }

    public boolean hmacVerify(byte[] key, short keyOffset, short keyLen,
                              byte[] data, short dataOffset, short dataLen,
                              byte[] mac, short macOffset, short macLen) {
        return mCryptoProvider.hmacVerify(key, keyOffset, keyLen,
                                    data, dataOffset, dataLen,
                                    mac, macOffset, macLen);
    }

    public boolean validateAuthToken(byte[] argsBuff,
    		short challengeOffset, short challengeLen,
    		short secureUserIdOffset, short secureUserIdLen,
    		short authenticatorIdOffset, short authenticatorIdLen,
    		short hardwareAuthenticatorTypeOffset, short hardwareAuthenticatorTypeLen,
    		short timeStampOffset, short timeStampLen,
    		short macOffset, short macLen,
    		short verificationTokenChallengeOffset, short verificationTokenChallengeLen,
    		short verificationTokenTimeStampOffset, short verificationTokenTimeStampLen,
    		short parametersVerifiedOffset, short parametersVerifiedLen,
    		short verificationTokensecurityLevelOffset, short verificationTokensecurityLevelLen,
    		short verificationTokenMacOffset, short verificationTokenMacLen) {
    	
    	AID keymasterAID = JCSystem.lookupAID(ICConstants.KEYMASTER_AID, (byte)0, (byte)ICConstants.KEYMASTER_AID.length);
		if(keymasterAID == null) {
			ISOException.throwIt((short)1);;
		}
		short argsLen = (short) (challengeLen + secureUserIdLen + authenticatorIdLen
								+ hardwareAuthenticatorTypeLen + timeStampLen + macLen
								+ verificationTokenChallengeLen + verificationTokenTimeStampLen
								+ parametersVerifiedLen + verificationTokensecurityLevelLen + verificationTokenMacLen);
		byte[] globalArgsArray = (byte[])JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, argsLen);
		byte[] scratchPad = (byte[])JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short)256);
		Util.arrayCopyNonAtomic(argsBuff, challengeOffset, globalArgsArray, challengeOffset, challengeLen);
		Util.arrayCopyNonAtomic(argsBuff, secureUserIdOffset, globalArgsArray, secureUserIdOffset, secureUserIdLen);
		Util.arrayCopyNonAtomic(argsBuff, authenticatorIdOffset, globalArgsArray, authenticatorIdOffset, authenticatorIdLen);
		Util.arrayCopyNonAtomic(argsBuff, hardwareAuthenticatorTypeOffset, globalArgsArray, hardwareAuthenticatorTypeOffset, hardwareAuthenticatorTypeLen);
		Util.arrayCopyNonAtomic(argsBuff, timeStampOffset, globalArgsArray, timeStampOffset, timeStampLen);
		Util.arrayCopyNonAtomic(argsBuff, macOffset, globalArgsArray, macOffset, macLen);
		Util.arrayCopyNonAtomic(argsBuff, verificationTokenChallengeOffset, globalArgsArray, verificationTokenChallengeOffset, verificationTokenChallengeLen);
		Util.arrayCopyNonAtomic(argsBuff, verificationTokenTimeStampOffset, globalArgsArray, verificationTokenTimeStampOffset, verificationTokenTimeStampLen);
		Util.arrayCopyNonAtomic(argsBuff, parametersVerifiedOffset, globalArgsArray, parametersVerifiedOffset, parametersVerifiedLen);
		Util.arrayCopyNonAtomic(argsBuff, verificationTokensecurityLevelOffset, globalArgsArray, verificationTokensecurityLevelOffset, verificationTokensecurityLevelLen);
		Util.arrayCopyNonAtomic(argsBuff, verificationTokenMacOffset, globalArgsArray, verificationTokenMacOffset, verificationTokenMacLen);
		Shareable sharable = JCSystem.getAppletShareableInterfaceObject(keymasterAID, (byte)1);
        boolean isVerified = ((KMAppletBridge)sharable).validateAuthTokensExt(
        			globalArgsArray,
            		challengeOffset, challengeLen,
            		secureUserIdOffset, secureUserIdLen,
            		authenticatorIdOffset, authenticatorIdLen,
            		hardwareAuthenticatorTypeOffset, hardwareAuthenticatorTypeLen,
            		timeStampOffset, timeStampLen,
            		macOffset, macLen,
            		verificationTokenChallengeOffset, verificationTokenChallengeLen,
            		verificationTokenTimeStampOffset, verificationTokenTimeStampLen,
            		parametersVerifiedOffset, parametersVerifiedLen,
            		verificationTokensecurityLevelOffset, verificationTokensecurityLevelLen,
            		verificationTokenMacOffset, verificationTokenMacLen,
        			scratchPad);
        JCSystem.requestObjectDeletion();
        return isVerified;
    }

    public boolean verifyCertByPubKey(byte[] cert, short certOffset, short certLen, byte[] pubKey, short pubKeyOffset, short pubKeyLen) {
        return mCryptoProvider.verifyCertByPubKey(cert, certOffset, certLen, pubKey, pubKeyOffset, pubKeyLen);
    }

	public short constructPublicKeyCertificate(byte[] pubKey, short pubKeyOffset, short pubKeyLen,
												byte[] proofOfBinding, short pobOffset, short pobLen,
												byte[] timeBuffer, short timeOffset,
												byte[] pubCertOut, short pubCertOutOffset) {
		Util.arrayCopyNonAtomic(X509_CERT_BASE, (short)0, pubCertOut, pubCertOutOffset, (short)X509_CERT_BASE.length);
		
		AID keymasterAID = JCSystem.lookupAID(ICConstants.KEYMASTER_AID, (byte)0, (byte)ICConstants.KEYMASTER_AID.length);
		if(keymasterAID == null) {
			ISOException.throwIt((short)1);;
		}
		//Not before date time
		byte[] globalOutArray = (byte[])JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short)257);
		Util.arrayCopyNonAtomic(timeBuffer, timeOffset, globalOutArray, (short)0, LONG_SIZE);
		Shareable sharable = JCSystem.getAppletShareableInterfaceObject(keymasterAID, (byte)1);
        short dateLen = ((KMAppletBridge)sharable).convertDate(globalOutArray, (short)0,
        													globalOutArray, (short)0);
        if(dateLen != (short)13) {
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(globalOutArray, (short)0, pubCertOut, (short)(pubCertOutOffset + X509_CERT_POS_VALID_NOT_BEFORE), dateLen);
    	//Not after
        ICUtil.incrementByteArray(timeBuffer, timeOffset, LONG_SIZE, ICConstants.ONE_YEAR_MS, (short)0, (byte)ICConstants.ONE_YEAR_MS.length);
        Util.arrayCopyNonAtomic(timeBuffer, timeOffset, globalOutArray, (short)0, LONG_SIZE);
		dateLen = ((KMAppletBridge)sharable).convertDate(globalOutArray, (short)0,
				globalOutArray, (short)0);
		if(dateLen != (short)13) {
        	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopyNonAtomic(globalOutArray, (short)0, pubCertOut, (short)(pubCertOutOffset + X509_CERT_POS_VALID_NOT_AFTER), dateLen);
		JCSystem.requestObjectDeletion();

		//Set public key length
		pubCertOut[(short) (pubCertOutOffset + X509_CERT_BASE.length - 2)] = (byte)(pubKeyLen + 1);
		Util.arrayCopyNonAtomic(pubKey, pubKeyOffset, pubCertOut, (short)(pubCertOutOffset + X509_CERT_BASE.length), pubKeyLen);
		Util.arrayCopyNonAtomic(X509_DER_POB, (short)0, pubCertOut, (short)(pubCertOutOffset + X509_CERT_BASE.length + pubKeyLen), (short)X509_DER_POB.length);

		Util.arrayCopyNonAtomic(proofOfBinding, pobOffset, pubCertOut, (short)(pubCertOutOffset + X509_CERT_BASE.length + pubKeyLen + X509_DER_POB.length), pobLen);
		short tbsCertLen = (short)(X509_CERT_BASE.length + pubKeyLen + X509_DER_POB.length + pobLen -  X509_CERT_POS_TOTAL_LEN - SHORT_SIZE);
		Util.arrayCopyNonAtomic(X509_DER_SIGNATURE, (short)0, pubCertOut, (short)(pubCertOutOffset + X509_CERT_POS_TOTAL_LEN + SHORT_SIZE + tbsCertLen), (short)(X509_DER_SIGNATURE.length));

		short signLen = ecSignWithSHA256Digest(pubCertOut, (short)(pubCertOutOffset + X509_CERT_POS_TOTAL_LEN + SHORT_SIZE), tbsCertLen, pubCertOut, (short)(pubCertOutOffset + X509_CERT_POS_TOTAL_LEN + SHORT_SIZE + tbsCertLen + X509_DER_SIGNATURE.length));
		pubCertOut[(short) (pubCertOutOffset + X509_CERT_POS_TOTAL_LEN + SHORT_SIZE + tbsCertLen + X509_DER_SIGNATURE.length - 2)] = (byte)(signLen + 1);
		Util.setShort(pubCertOut, (short) (pubCertOutOffset + X509_CERT_POS_TOTAL_LEN), (short)(tbsCertLen + X509_DER_SIGNATURE.length + signLen));

		return (short)(X509_CERT_POS_TOTAL_LEN + SHORT_SIZE + tbsCertLen + X509_DER_SIGNATURE.length + signLen);
	}

}
