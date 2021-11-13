package com.android.se.ready;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Shareable;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

import static com.android.se.ready.ICConstants.LONG_SIZE;

import com.android.javacard.keymaster.*;

public class JCICStoreApplet extends Applet implements ExtendedLength {

    // Version identifier of this Applet
    public static final byte[] VERSION = { (byte) 0x00, (byte) 0x02, (byte) 0x00 };
    //Identity Credential Reference Implementation
    private static final byte[] STR_CREDENTIAL_SOTRE_NAME = {(byte) 0x49, (byte) 0x64, (byte) 0x65, (byte) 0x6e, (byte) 0x74, (byte) 0x69, (byte) 0x74, (byte) 0x79,
    														(byte) 0x20, (byte) 0x43, (byte) 0x72, (byte) 0x65, (byte) 0x64, (byte) 0x65, (byte) 0x6e, (byte) 0x74,
    														(byte) 0x69, (byte) 0x61, (byte) 0x6c, (byte) 0x20, (byte) 0x4a, (byte) 0x61, (byte) 0x76, (byte) 0x61,
    														(byte) 0x43, (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x20, (byte) 0x49, (byte) 0x6d, (byte) 0x70,
    														(byte) 0x6c, (byte) 0x65, (byte) 0x6d, (byte) 0x65, (byte) 0x6e, (byte) 0x74, (byte) 0x61, (byte) 0x74,
    														(byte) 0x69, (byte) 0x6f, (byte) 0x6e};

    //Google
    private static final byte[] STR_CREDENTIAL_SOTRE_AUTHIR_NAME = {(byte) 0x47, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65};
    
    public static final short DATA_CHUNK_SIZE = (short)1024;
    public static final short MAX_APDU_SIZE = (short)230;

    public static final boolean IS_DIRECT_ACCESS_ENABLED = false;
    
    private final CBORDecoder mCBORDecoder;

    private final CBOREncoder mCBOREncoder;
    
    private final JCICProvisioning mProvisioning;
    
    private final JCICPresentation mPresentation;

    private final APDUManager mAPDUManager;
    // Temporary buffer for all operations
    private static ICByteBlob mTempBuffer;

    public JCICStoreApplet(ICryptoProvider cryptoProvider) {
        mCBORDecoder = new CBORDecoder();
        
        mCBOREncoder = new CBOREncoder();
        
        byte[] buffer = JCSystem.makeTransientByteArray((short)(ICConstants.TEMP_BUFFER_SIZE + ICConstants.AES_GCM_IV_SIZE + ICConstants.AES_GCM_TAG_SIZE), JCSystem.CLEAR_ON_RESET);
        
        mTempBuffer = new ICByteBlob(buffer, (short)0, (short)buffer.length);

        mAPDUManager = new APDUManager((byte) (ICConstants.AES_GCM_IV_SIZE + ICConstants.AES_GCM_TAG_SIZE));

        CryptoManager cryptoManager = new CryptoManager(cryptoProvider);

		mProvisioning = new JCICProvisioning(cryptoManager, mCBORDecoder, mCBOREncoder);
		
		mPresentation = new JCICPresentation(cryptoManager, mCBORDecoder, mCBOREncoder);

    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        JCICStoreApplet applet = new JCICStoreApplet(new CryptoProviderImpl());
        applet.register();
    }
    
    public boolean select() {
		return super.select();
	}

	public void process(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();

        if (!mAPDUManager.process(apdu)) {
            return;
        }


        if (this.selectingApplet()) {
        	mProvisioning.reset();
        	mPresentation.reset();
            processSelectApplet(apdu);
            return;
        }


        if (!apdu.isISOInterindustryCLA()) {
            switch (buf[ISO7816.OFFSET_INS]) {
	            case ISO7816.INS_ICS_GET_VERSION:
	                processGetVersion();
	                break;
	            case ISO7816.INS_ICS_PING:
	                processPing();
	                break;
	            case ISO7816.INS_ICS_GET_HARDWARE_INFO:
	                processGetHardwareInfo();
	                break;
	            case ISO7816.INS_ICS_GET_ATTEST_CERT_CHAIN:
	                processGetAttestCertChain();
	                break;
	            case ISO7816.INS_ICS_PROVISIONING_INIT:
	            case ISO7816.INS_ICS_CREATE_CREDENTIAL_KEY:
	            case ISO7816.INS_ICS_START_PERSONALIZATION:
	            case ISO7816.INS_ICS_ADD_ACCESS_CONTROL_PROFILE:
	            case ISO7816.INS_ICS_BEGIN_ADD_ENTRY:
	            case ISO7816.INS_ICS_ADD_ENTRY_VALUE:
	            case ISO7816.INS_ICS_FINISH_ADDING_ENTRIES:
	            case ISO7816.INS_ICS_FINISH_GET_CREDENTIAL_DATA:
                case ISO7816.INS_ICS_UPDATE_CREDENTIAL:
	            	mProvisioning.processAPDU(mAPDUManager);
	            	break;
                case ISO7816.INS_ICS_PRESENTATION_INIT:
                case ISO7816.INS_ICS_CREATE_EPHEMERAL_KEY_PAIR:
                case ISO7816.INS_ICS_CREATE_AUTH_CHALLENGE:
                case ISO7816.INS_ICS_START_RETRIEVAL:
                case ISO7816.INS_ICS_SET_AUTH_TOKEN:
                case ISO7816.INS_ICS_PUSH_READER_CERT:
                case ISO7816.INS_ICS_VALIDATE_ACCESS_CONTROL_PROFILES:
                case ISO7816.INS_ICS_VALIDATE_REQUEST_MESSAGE:
                case ISO7816.INS_ICS_CAL_MAC_KEY:
                case ISO7816.INS_ICS_START_RETRIEVE_ENTRY_VALUE:
                case ISO7816.INS_ICS_RETRIEVE_ENTRY_VALUE:
                case ISO7816.INS_ICS_FINISH_RETRIEVAL:
                case ISO7816.INS_ICS_GENERATE_SIGNING_KEY_PAIR:
                case ISO7816.INS_ICS_PROVE_OWNERSHIP:
                case ISO7816.INS_ICS_DELETE_CREDENTIAL:
                    mPresentation.processAPDU(mAPDUManager);
                    break;
	            default:
	                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } 

        mAPDUManager.sendAll();
	}

    /**
     * Process the select command and return hardware configuration in the select
     * applet command.
     */
    private void processSelectApplet(APDU apdu){
        mAPDUManager.setOutgoing();
        byte[] outBuff = mAPDUManager.getSendBuffer();
        Util.setShort(outBuff, (short) 0, MAX_APDU_SIZE);
        Util.setShort(outBuff, (short) 2, DATA_CHUNK_SIZE);
        Util.setShort(outBuff, (short) 4, CryptoManager.getAESKeySize());

        mAPDUManager.setOutgoingLength((short) 6);
        mAPDUManager.sendAll();
    }

	public static ICByteBlob getTempByteBlob() {
		return mTempBuffer;
	}

	/**
     * Process incoming PING requests.
     */
    private void processPing() {
        final byte[] inBuffer = mAPDUManager.getReceiveBuffer();
        
        short pingType = Util.getShort(inBuffer, ISO7816.OFFSET_P1);

        if (pingType == 0) {
            // Do nothing
        } else if (pingType == 1) {
            // Respond with incoming data
            final short lc = mAPDUManager.receiveAll();
            final short le = mAPDUManager.setOutgoing();
            final byte[] outBuffer = mAPDUManager.getSendBuffer();
            
            short outLen = Util.arrayCopyNonAtomic(inBuffer, mAPDUManager.getOffsetIncomingData(), outBuffer, (short)0, ICUtil.min(lc, le));
            
            mAPDUManager.setOutgoingLength(outLen);
        }
    }
    
    /**
     * Process the GET VERSION command and return the current Applet version
     */
    private void processGetVersion() {
        final byte[] inBuffer = mAPDUManager.getReceiveBuffer();

        if (Util.getShort(inBuffer, ISO7816.OFFSET_P1) != 0x0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short le = mAPDUManager.setOutgoing();
        final byte[] outBuffer = mAPDUManager.getSendBuffer();

        if (le < (short) VERSION.length) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short outLength = Util.arrayCopyNonAtomic(VERSION, (short) 0, outBuffer, (short) 0, (short) VERSION.length);

        mAPDUManager.setOutgoingLength(outLength);
    }

    /**
     * Process the GET HardwareInfo command
     */
    private void processGetHardwareInfo() {
        final byte[] inBuffer = mAPDUManager.getReceiveBuffer();

        if (Util.getShort(inBuffer, ISO7816.OFFSET_P1) != 0x0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short le = mAPDUManager.setOutgoing();
        final byte[] outBuffer = mAPDUManager.getSendBuffer();

        mCBOREncoder.init(outBuffer, (short)0, le);
        mCBOREncoder.startArray((short)2);
        mCBOREncoder.encodeUInt8((byte)0);//Success
        mCBOREncoder.startArray((short)5);
        mCBOREncoder.encodeTextString(STR_CREDENTIAL_SOTRE_NAME, (short) 0, (short)STR_CREDENTIAL_SOTRE_NAME.length);
        mCBOREncoder.encodeTextString(STR_CREDENTIAL_SOTRE_AUTHIR_NAME, (short) 0, (short)STR_CREDENTIAL_SOTRE_AUTHIR_NAME.length);
        mCBOREncoder.encodeUInt16(DATA_CHUNK_SIZE);
        mCBOREncoder.encodeBoolean(IS_DIRECT_ACCESS_ENABLED);
        mCBOREncoder.startArray((short) 0);
        
        mAPDUManager.setOutgoingLength(mCBOREncoder.getCurrentOffset());
    }
    
    private void processGetAttestCertChain() {
    	mAPDUManager.receiveAll();
        byte[] receiveBuffer = mAPDUManager.getReceiveBuffer();
        short receivingDataOffset = mAPDUManager.getOffsetIncomingData();
        short receivingDataLength = mAPDUManager.getReceivingLength();
		byte[] tempBuffer = JCICStoreApplet.getTempByteBlob().getBuffer();
		short tempBufferOffset = JCICStoreApplet.getTempByteBlob().getStartOff();

        mCBORDecoder.init(receiveBuffer, receivingDataOffset, receivingDataLength);
        mCBORDecoder.readMajorType(CBORBase.TYPE_ARRAY);
        short nowMsOffset = (short)tempBufferOffset;
        short intSize = mCBORDecoder.getIntegerSize();
        ICUtil.readUInt(mCBORDecoder, tempBuffer, (short)(nowMsOffset + LONG_SIZE - intSize));
        short expireTimeOffset = (short)(nowMsOffset + LONG_SIZE);
        intSize = mCBORDecoder.getIntegerSize();
        ICUtil.readUInt(mCBORDecoder, tempBuffer, (short)(expireTimeOffset + LONG_SIZE - intSize));
    	try {
	    	//We will take byte array of double size of temp buffer size which is required to copy cert chain
			byte[] globalTempBuffer = (byte[])JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short)(1024));
	    	AID keymasterAID = JCSystem.lookupAID(ICConstants.KEYMASTER_AID, (byte)0, (byte)ICConstants.KEYMASTER_AID.length);
			if(keymasterAID == null) {
				ISOException.throwIt((short)1);;
			}
			Shareable shareable = JCSystem.getAppletShareableInterfaceObject(keymasterAID, (byte)1);
			byte[] argsBuffer = (byte[])JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short) (LONG_SIZE + LONG_SIZE));
	    	Util.arrayCopyNonAtomic(tempBuffer, nowMsOffset, argsBuffer, nowMsOffset, LONG_SIZE);
			Util.arrayCopyNonAtomic(tempBuffer, expireTimeOffset, argsBuffer, expireTimeOffset, LONG_SIZE);
			
	    	byte[] globalScratchPad = (byte[])JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_BYTE, (short)(256));
			short[] outLengths = (short[])JCSystem.makeGlobalArray(JCSystem.ARRAY_TYPE_SHORT, (short)(2));
			short outBlobOffset = (short)0;
			((KMAppletBridge) shareable).getAttestCertChainAndKey(argsBuffer, (short)0, LONG_SIZE, globalTempBuffer, outBlobOffset, (short)globalTempBuffer.length, outLengths, globalScratchPad);
	    	
	    	mAPDUManager.setOutgoing();
	        byte[] outBuffer = mAPDUManager.getSendBuffer();
	        short le = mAPDUManager.getOutbufferLength();
	        mCBOREncoder.init(outBuffer, (short) 0, le);
	        mCBOREncoder.startArray((short)2);
	        mCBOREncoder.encodeUInt8((byte)0); //Success
	        mCBOREncoder.startArray((short)2);
	        mCBOREncoder.encodeByteString(globalTempBuffer, outBlobOffset, outLengths[(short)0]);
	        mCBOREncoder.encodeByteString(globalTempBuffer, (short)(outBlobOffset + outLengths[(short)0]), outLengths[(short)1]);
	        mAPDUManager.setOutgoingLength(mCBOREncoder.getCurrentOffset());
    	} finally {
    		JCSystem.requestObjectDeletion();
    	}
    }
}
