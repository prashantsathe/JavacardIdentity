package android.security.jcic;

import com.android.javacard.keymaster.*;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;

final class CryptoProviderImpl implements ICryptoProvider{
	private final Signature mHMACSignature;
	//private final KeyPair mECKeyPair1;
	private final KeyAgreement mECDHAgreement;
	private final Signature signerNoDigest;
	private final Signature signerWithSha256;
	private final byte[] keymaterAIDBytes = new byte[] {(byte)0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x02, 0x0C, 0x01, 0x02, 0x01};
	private final KeyPair ecKeyPair;
	//private final AESKey aesKey;
    
    //private final AEADCipher aesGcmCipher;
	private final HMACKey mHmacKey;
	private final byte[] tempBuffer;
    
	CryptoProviderImpl() {
		mHMACSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
		/*mECKeyPair1 = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
		ECPrivateKey privKey1 = (ECPrivateKey) mECKeyPair1.getPrivate();
		Secp256r1.configureECKeyParameters(privKey1);
		ECPublicKey pubKey1 = (ECPublicKey) mECKeyPair1.getPublic();
		Secp256r1.configureECKeyParameters(pubKey1);*/
		
		mECDHAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
		
		ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
		ECPrivateKey privKey = (ECPrivateKey) ecKeyPair.getPrivate();
		Secp256r1.configureECKeyParameters(privKey);
		ECPublicKey pubKey = (ECPublicKey) ecKeyPair.getPublic();
		Secp256r1.configureECKeyParameters(pubKey);
		
		signerNoDigest = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		
		signerWithSha256 = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		//aesKey = (AESKey) KeyBuilder.buildKey(
		//        KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		//aesGcmCipher = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, true);

		mHmacKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC,
				(short)256, false);
		
		tempBuffer = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_RESET);
	}
	
	private KMSEProvider getSEProvider() {
		//if(true)return null;
		AID keymasterAID = JCSystem.lookupAID(keymaterAIDBytes, (byte)0, (byte)keymaterAIDBytes.length);
		if(keymasterAID == null) {
			return null;
		}
		KMSEProvider kmSEProvider = (KMSEProvider)JCSystem.getAppletShareableInterfaceObject(keymasterAID, (byte)0);
		return kmSEProvider;
	}

	public void createECKey(byte[] privKeyBuf, short privKeyStart, short privKeyMaxLength,
			byte[] pubModBuf, short pubModStart, short pubModMaxLength, short[] lengths) {
		KMSEProvider seProvider = getSEProvider();
		if(seProvider != null) {
			short privKeyOffset = (byte)0;
			short pubKeyOffset = CryptoManager.EC_KEY_SIZE;
			byte[] tempGlobalByteArray = (byte[])JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short)(privKeyMaxLength + pubModMaxLength));
			short[] tempGlobalShortArray = (short[])JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_SHORT, (short)lengths.length);
			seProvider.createAsymmetricKey(KMType.EC, tempGlobalByteArray, privKeyOffset, CryptoManager.EC_KEY_SIZE,
					tempGlobalByteArray, pubKeyOffset, (byte)65, tempGlobalShortArray);
	
			Util.arrayCopyNonAtomic(tempGlobalByteArray, privKeyOffset, privKeyBuf, privKeyStart, tempGlobalShortArray[0]);
			Util.arrayCopyNonAtomic(tempGlobalByteArray, pubKeyOffset, pubModBuf, pubModStart, tempGlobalShortArray[1]);
			lengths[0] = tempGlobalShortArray[0];
			lengths[1] = tempGlobalShortArray[1];
			JCSystem.requestObjectDeletion();
		} else {
			ecKeyPair.genKeyPair();
			ECPrivateKey privKey = (ECPrivateKey) ecKeyPair.getPrivate();
			lengths[0] = privKey.getS(privKeyBuf, privKeyStart);
			ECPublicKey pubKey = (ECPublicKey) ecKeyPair.getPublic();
			lengths[1] = pubKey.getW(pubModBuf, pubModStart);
		}
	}

	public short ecSignWithNoDigest(byte[] privKeyBuf, short privKeyStart, short privKeyLength,
									byte[] data, short dataStart, short dataLength,
									byte[] outSign, short outSignStart) {

		/*KMSEProvider seProvider = getSEProvider();
		if(seProvider != null) {
			byte[] tempGlobalByteArray = (byte[])JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short)(privKeyLength + dataLength + (short)72));
			short privKeyOffset = (byte)0;
			short dataOffset = privKeyLength;
			short outSignOffset = (short)(dataOffset + dataLength);
			Util.arrayCopyNonAtomic(privKeyBuf, privKeyStart, tempGlobalByteArray, privKeyOffset, privKeyLength);
			Util.arrayCopyNonAtomic(data, dataStart, tempGlobalByteArray, dataOffset, dataLength);
			KMOperation signer = seProvider.initAsymmetricOperation(KMType.SIGN, KMType.EC,  KMType.PADDING_NONE , KMType.DIGEST_NONE,
					tempGlobalByteArray, privKeyOffset, privKeyLength, //Private key
					tempGlobalByteArray, (short)0, (short)0); //Public key
	    	
			short signLen = signer.sign(tempGlobalByteArray, dataOffset, dataLength, tempGlobalByteArray, outSignOffset);
			Util.arrayCopyNonAtomic(tempGlobalByteArray, outSignOffset, outSign, outSignOffset, signLen);
			JCSystem.requestObjectDeletion();
			return signLen;
		} else {*/
			ECPrivateKey key = (ECPrivateKey) ecKeyPair.getPrivate();
			key.setS(privKeyBuf, privKeyStart, privKeyLength);
			signerNoDigest.init(key, Signature.MODE_SIGN);
			return signerNoDigest.signPreComputedHash(data, dataStart, dataLength, outSign, outSignStart);
		//}
	}

	public short aesGCMEncrypt(byte[] aesKeyBuff, short aesKeyStart, short aesKeyLen,
			byte[] data, short dataStart, short dataLen,
			byte[] encData, short encDataStart,
			byte[] nonce, short nonceStart, short nonceLen,
			byte[] authData, short authDataStart, short authDataLen,
			byte[] authTag, short authTagStart, short authTagLen) {

		KMSEProvider seProvider = getSEProvider();
		//if(seProvider != null) {
			byte[] tempGlobalByteArray = (byte[])JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short)(aesKeyLen + dataLen + dataLen + nonceLen + authDataLen + authTagLen));
			short aesKeyOffset = (byte)0;
			short dataOffset = (short)(aesKeyOffset + aesKeyLen);
			short encDataOffset = (short)(dataOffset + dataLen);
			short nonceOffset = (short)(encDataOffset + dataLen);
			short authDataOffset = (short)(nonceOffset + nonceLen);
			short authTagOffset = (short)(authDataOffset + authDataLen);
			Util.arrayCopyNonAtomic(aesKeyBuff, aesKeyStart, tempGlobalByteArray, aesKeyOffset, aesKeyLen);
			Util.arrayCopyNonAtomic(data, dataStart, tempGlobalByteArray, dataOffset, dataLen);
			Util.arrayCopyNonAtomic(nonce, nonceStart, tempGlobalByteArray, nonceOffset, nonceLen);
			Util.arrayCopyNonAtomic(authData, authDataStart, tempGlobalByteArray, authDataOffset, authDataLen);
			
			short encLen = seProvider.aesGCMEncrypt(tempGlobalByteArray, aesKeyOffset, aesKeyLen, tempGlobalByteArray, dataOffset,
					dataLen, tempGlobalByteArray, encDataOffset, tempGlobalByteArray, nonceOffset, nonceLen,
					tempGlobalByteArray, authDataOffset, authDataLen, tempGlobalByteArray, authTagOffset, authTagLen);
			
			Util.arrayCopyNonAtomic(tempGlobalByteArray, encDataOffset, encData, encDataStart, encLen);
			Util.arrayCopyNonAtomic(tempGlobalByteArray, authTagOffset, authTag, authTagStart, authTagLen);
			JCSystem.requestObjectDeletion();
			return encLen;
		/*} else {
			this.aesKey.setKey(aesKeyBuff, aesKeyStart);
			aesGcmCipher.init(this.aesKey, Cipher.MODE_ENCRYPT, nonce, nonceStart, nonceLen);
	
		    aesGcmCipher.updateAAD(authData, authDataStart, authDataLen);
		    short ciphLen = aesGcmCipher.doFinal(data, dataStart, dataLen, encData, encDataStart);
		    aesGcmCipher.retrieveTag(authTag, authTagStart, authTagLen);
		    return ciphLen;
		}*/
	}

	public boolean aesGCMDecrypt(byte[] aesKeyBuff, short aesKeyStart, short aesKeyLen, 
			byte[] data, short dataStart, short dataLen,
			byte[] encData, short encDataStart,
			byte[] nonce, short nonceStart, short nonceLen,
			byte[] authData, short authDataStart, short authDataLen,
			byte[] authTag, short authTagStart, short authTagLen) {
		KMSEProvider seProvider = getSEProvider();
		//if(seProvider != null) {
			byte[] tempGlobalByteArray = (byte[])JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short)(aesKeyLen + dataLen + dataLen + nonceLen + authDataLen + authTagLen));
			short aesKeyOffset = (byte)0;
			short dataOffset = (short)(aesKeyOffset + aesKeyLen);
			short encDataOffset = (short)(dataOffset + dataLen);
			short nonceOffset = (short)(encDataOffset + dataLen);
			short authDataOffset = (short)(nonceOffset + nonceLen);
			short authTagOffset = (short)(authDataOffset + authDataLen);
			Util.arrayCopyNonAtomic(aesKeyBuff, aesKeyStart, tempGlobalByteArray, aesKeyOffset, aesKeyLen);
			Util.arrayCopyNonAtomic(data, dataStart, tempGlobalByteArray, dataOffset, dataLen);
			Util.arrayCopyNonAtomic(encData, encDataStart, tempGlobalByteArray, encDataOffset, dataLen);
			Util.arrayCopyNonAtomic(nonce, nonceStart, tempGlobalByteArray, nonceOffset, nonceLen);
			Util.arrayCopyNonAtomic(authData, authDataStart, tempGlobalByteArray, authDataOffset, authDataLen);
			Util.arrayCopyNonAtomic(authTag, authTagStart, tempGlobalByteArray, authTagOffset, authTagLen);
			
			boolean isSuccess = seProvider.aesGCMDecrypt(tempGlobalByteArray, aesKeyOffset, aesKeyLen, tempGlobalByteArray, dataOffset,
					dataLen, tempGlobalByteArray, encDataOffset, tempGlobalByteArray, nonceOffset, nonceLen,
					tempGlobalByteArray, authDataOffset, authDataLen, tempGlobalByteArray, authTagOffset, authTagLen);
	
			Util.arrayCopyNonAtomic(tempGlobalByteArray, encDataOffset, encData, encDataStart, dataLen);
			JCSystem.requestObjectDeletion();
			return isSuccess;
		/*} else {
			this.aesKey.setKey(aesKeyBuff, aesKeyStart);
			aesGcmCipher.init(this.aesKey, Cipher.MODE_DECRYPT, nonce, nonceStart, nonceLen);
	
		    aesGcmCipher.updateAAD(authData, authDataStart, authDataLen);
		    aesGcmCipher.doFinal(data, dataStart, dataLen, encData, encDataStart);
		    return aesGcmCipher.verifyTag(authTag, authTagStart, authTagLen, CryptoManager.AES_GCM_TAG_SIZE);
		}*/
	}

	public short ecSignWithSHA256Digest(byte[] privKeyBuf, short privKeyStart, short privKeyLength,
										byte[] data, short dataStart, short dataLength,
										byte[] outSign, short outSignStart) {
		KMSEProvider seProvider = getSEProvider();
		if(seProvider != null) {
			byte[] tempGlobalByteArray = (byte[])JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short)(privKeyLength + dataLength + (short)72));
			short privKeyOffset = (byte)0;
			short dataOffset = (short)(privKeyOffset + privKeyLength);
			short outSignOffset = (short)(dataOffset + dataLength);
			Util.arrayCopyNonAtomic(privKeyBuf, privKeyStart, tempGlobalByteArray, privKeyOffset, privKeyLength);
			Util.arrayCopyNonAtomic(data, dataStart, tempGlobalByteArray, dataOffset, dataLength);
			
			KMOperation signer = getSEProvider().initAsymmetricOperation(KMType.SIGN, KMType.EC,  KMType.PADDING_NONE , KMType.SHA2_256,
					tempGlobalByteArray, privKeyOffset, privKeyLength, //Private key
					tempGlobalByteArray, (short)0, (short)0); //Public key
			short signLen = signer.sign(tempGlobalByteArray, dataOffset, dataLength, tempGlobalByteArray, outSignOffset);
			
			Util.arrayCopyNonAtomic(tempGlobalByteArray, outSignOffset, outSign, outSignStart, signLen);
			JCSystem.requestObjectDeletion();
			getSEProvider().releaseAllOperations();
			return signLen;
		} else {
			ECPrivateKey key = (ECPrivateKey) ecKeyPair.getPrivate();
			//Secp256r1.configureECKeyParameters(key);
			key.setS(privKeyBuf, privKeyStart, privKeyLength);
			signerWithSha256.init(key, Signature.MODE_SIGN);
			return signerWithSha256.sign(data, dataStart, dataLength, outSign, outSignStart);
		}
	}

	public boolean ecVerifyWithNoDigest(byte[] pubKeyBuf, short pubKeyStart, short pubKeyLength,
                                        byte[] data, short dataStart, short dataLength,
                                        byte[] signBuf, short signStart, short signLength) {
		ECPublicKey pubKey = (ECPublicKey)ecKeyPair.getPublic();
		//Secp256r1.configureECKeyParameters(pubKey);
		pubKey.setW(pubKeyBuf, pubKeyStart, pubKeyLength);
		signerNoDigest.init(pubKey, Signature.MODE_VERIFY);
		return signerNoDigest.verifyPreComputedHash(data, dataStart, dataLength, signBuf, signStart, signLength);
	}

	public short createECDHSecret(byte[] privKey, short privKeyOffset, short privKeyLen,
								  byte[] pubKey, short pubKeyOffset, short pubKeyLen,
								  byte[] outSecret, short outSecretOffset) {
		ECPrivateKey privateKey = (ECPrivateKey) ecKeyPair.getPrivate();
		//Secp256r1.configureECKeyParameters(privateKey);
		privateKey.setS(privKey, privKeyOffset, privKeyLen);
		mECDHAgreement.init(privateKey);
		short result = mECDHAgreement.generateSecret(pubKey, pubKeyOffset, pubKeyLen, outSecret, outSecretOffset);
		return result;
	}

	public short hkdf(byte[] sharedSecret, short sharedSecretOffset, short sharedSecretLen,
					  byte[] salt, short saltOffset, short saltLen,
					  byte[] info, short infoOffset, short infoLen,
					  byte[] outDerivedKey, short outDerivedKeyOffset, short expectedDerivedKeyLen) {
		// HMAC_extract
		short prkLen = hkdfExtract(sharedSecret, sharedSecretOffset, sharedSecretLen, salt, saltOffset, saltLen, tempBuffer, (short) 0);
		//HMAC_expand
		return hkdfExpand(tempBuffer, (short) 0, prkLen, info, infoOffset, infoLen, outDerivedKey, outDerivedKeyOffset, expectedDerivedKeyLen);
	}

	private short hkdfExtract(byte[] ikm, short ikmOff, short ikmLen, byte[] salt, short saltOff, short saltLen,
							  byte[] out, short off) {
		// https://tools.ietf.org/html/rfc5869#section-2.2
		HMACKey hmacKey = createHMACKey(salt, saltOff, saltLen);
		mHMACSignature.init(hmacKey, Signature.MODE_SIGN);
		return mHMACSignature.sign(ikm, ikmOff, ikmLen, out, off);
	}

	private short hkdfExpand(byte[] prk, short prkOff, short prkLen, byte[] info, short infoOff, short infoLen,
							 byte[] out, short outOff, short outLen) {
		// https://tools.ietf.org/html/rfc5869#section-2.3
		short digestLen = (short) 32; // SHA256 digest length.
		// Calculate no of iterations N.
		short n = (short) ((short)(outLen + digestLen - 1) / digestLen);
		if (n > 255) {
			CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
		}
		HMACKey hmacKey = createHMACKey(prk, prkOff, prkLen);
		byte[] previousOutput = tempBuffer; // Length of output 32.
		byte[] cnt = {(byte) 0};
		short bytesCopied = 0;
		short len = 0;
		for (short i = 0; i < n; i++) {
			cnt[0]++;
			mHMACSignature.init(hmacKey, Signature.MODE_SIGN);
			if (i != 0)
				mHMACSignature.update(previousOutput, (short) 0, (short) 32);
			mHMACSignature.update(info, infoOff, infoLen);
			len = mHMACSignature.sign(cnt, (short) 0, (short) 1, previousOutput, (short) 0);
			if ((short) (bytesCopied + len) > outLen) {
				len = (short) (outLen - bytesCopied);
			}
			Util.arrayCopyNonAtomic(previousOutput, (short) 0, out, (short) (outOff + bytesCopied), len);
			bytesCopied += len;
		}
		return outLen;
	}
	public HMACKey createHMACKey(byte[] secretBuffer, short secretOff, short secretLength) {
		mHmacKey.setKey(secretBuffer, secretOff, secretLength);
		return mHmacKey;
	}

	public boolean hmacVerify(byte[] key, short keyOffset, short keyLen, byte[] data, short dataOffset, short dataLen, byte[] mac, short macOffset, short macLen) {
		HMACKey hmacKey = createHMACKey(key, keyOffset, keyLen);
		mHMACSignature.init(hmacKey, Signature.MODE_VERIFY);
		return mHMACSignature.verify(data, dataOffset, dataLen, mac, macOffset, macLen);
	}

	public boolean verifyCertByPubKey(byte[] cert, short certOffset, short certLen,
									  byte[] pubKey, short pubKeyOffset, short pubKeyLen) {
		if(certLen <= 0 || cert[0] != 0x30) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		short tbsStart = 0;
		for(short i = (short) (certOffset + 1); i < (short)(certOffset + 5); i++) {
			if(cert[i] == 0x30) {
				tbsStart = i;
				break;
			}
		}
		if(tbsStart == 0) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		short tbsLen;
		if(cert[(short)(tbsStart + 1)] == (byte)0x81) {
			tbsLen = (short)(cert[(short)(tbsStart + 2)] & 0x00FF);
			tbsLen += 3;
		} else if(cert[(short)(tbsStart + 1)] == (byte)0x82) {
			tbsLen = Util.getShort(cert, (short) (tbsStart + 2));
			tbsLen += 4;
		} else {
			tbsLen = (short)(cert[(short)(tbsStart + 1)] & 0x00FF);
			tbsLen += 2;
		}

		short signSeqStart = (short)(tbsStart + tbsLen + (byte)12/*OID TAG*/);
		if(cert[signSeqStart] != 0x03 && cert[(short)(signSeqStart + (byte)2)] != 0x00) {
			ISOException.throwIt(ISO7816.SW_DATA_INVALID);
		}
		byte signLen = (byte)(cert[(short)(signSeqStart + (byte)1)] - (byte)1);//Actual signature Bit string starts after 0x00. signature len expected around 70-72
		
		ECPublicKey publicKey = (ECPublicKey)ecKeyPair.getPublic();
		//Secp256r1.configureECKeyParameters(publicKey);
		publicKey.setW(pubKey, pubKeyOffset, pubKeyLen);
		signerWithSha256.init(publicKey, Signature.MODE_VERIFY);
		return signerWithSha256.verify(cert, tbsStart, tbsLen, cert, (short) (certOffset + certLen - signLen), signLen);
	}
}
