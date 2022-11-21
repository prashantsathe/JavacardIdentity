/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_HARDWARE_IDENTITY_JC_SECUREHARDWAREPROXY_H
#define ANDROID_HARDWARE_IDENTITY_JC_SECUREHARDWAREPROXY_H

#include "jcic_transport/AppletConnection.h"
#include "SecureHardwareProxy.h"


// The size of an ECSDA signature using P-256.

//

// The R and S values are stored here, first R then S.

//

#define JCIC_ECDSA_P256_SIGNATURE_SIZE 64


// The size of a P-256 private key.

//

#define JCIC_P256_PRIV_KEY_SIZE 32


namespace android::hardware::identity {

// This implementation uses javacard IC implementation.
//
class JCSecureHardwareProxy : public SecureHardwareProxy {
  public:
    JCSecureHardwareProxy();
    virtual ~JCSecureHardwareProxy();

    bool getHardwareInfo(string* storeName, string* storeAuthorName,
                                 int32_t* gcmChunkSize, bool* isDirectAccess, vector<string>* supportedDocTypes) override;
  protected:
    AppletConnection mAppletConnection;
};

// This implementation uses javacard IC implementation.
//
class JCSecureHardwareProvisioningProxy : public SecureHardwareProvisioningProxy {
  public:
    JCSecureHardwareProvisioningProxy();
    virtual ~JCSecureHardwareProvisioningProxy();

    bool initialize(bool testCredential) override;

    bool initializeForUpdate(bool testCredential, const string& docType,
                             const vector<uint8_t>& encryptedCredentialKeys) override;

    size_t getHwChunkSize() override;

    bool shutdown() override;

    // Returns public key certificate.
    optional<vector<uint8_t>> createCredentialKey(const vector<uint8_t>& challenge,
                                                  const vector<uint8_t>& applicationId) override;

    optional<vector<uint8_t>> createCredentialKeyUsingRkp(
            const vector<uint8_t>& challenge, const vector<uint8_t>& applicationId,
            const vector<uint8_t>& attestationKeyBlob,
            const vector<uint8_t>& attestationKeyCert) override;

    bool startPersonalization(int accessControlProfileCount, const vector<int>& entryCounts,
                              const string& docType,
                              size_t expectedProofOfProvisioningSize) override;

    // Returns MAC (28 bytes).
    optional<vector<uint8_t>> addAccessControlProfile(int id,
                                                      const vector<uint8_t>& readerCertificate,
                                                      bool userAuthenticationRequired,
                                                      uint64_t timeoutMillis,
                                                      uint64_t secureUserId) override;

    bool beginAddEntry(const vector<int>& accessControlProfileIds, const string& nameSpace,
                       const string& name, uint64_t entrySize) override;

    // Returns encryptedContent.
    optional<vector<uint8_t>> addEntryValue(const vector<int>& accessControlProfileIds,
                                            const string& nameSpace, const string& name,
                                            const vector<uint8_t>& content) override;

    // Returns signatureOfToBeSigned (EIC_ECDSA_P256_SIGNATURE_SIZE bytes).
    optional<vector<uint8_t>> finishAddingEntries() override;

    // Returns encryptedCredentialKeys (80 bytes).
    optional<vector<uint8_t>> finishGetCredentialData(const string& docType) override;

  protected:
    bool isTestCredential;
    // See docs for id_.
    //
    bool validateId(const string& callerName);

    // On the HAL side we keep track of the ID that was assigned to the libeic object
    // created in secure hardware. For every call into libeic we validate that this
    // identifier matches what is on the secure side. This is what the validateId()
    // method does.
    //
    uint32_t id_ = 0;
    AppletConnection mAppletConnection;
};

// This implementation uses libEmbeddedIC in-process.
//
class JCSecureHardwareSessionProxy : public SecureHardwareSessionProxy {
  public:
    JCSecureHardwareSessionProxy() = default;
    virtual ~JCSecureHardwareSessionProxy();

    bool initialize() override;

    bool shutdown() override;

    optional<uint64_t> getAuthChallenge() override;

    optional<uint32_t> getId() override;

    // Returns private key
    optional<vector<uint8_t>> getEphemeralKeyPair() override;

    bool setReaderEphemeralPublicKey(const vector<uint8_t>& readerEphemeralPublicKey) override;

    bool setSessionTranscript(const vector<uint8_t>& sessionTranscript) override;

  protected:
    // See docs for id_.
    //
    bool validateId(const string& callerName);

    // On the HAL side we keep track of the ID that was assigned to the libeic object
    // created in secure hardware. For every call into libeic we validate that this
    // identifier matches what is on the secure side. This is what the validateId()
    // method does.
    //
    uint32_t id_ = 0;
};


// This implementation uses javacard IC implementation.
//
class JCSecureHardwarePresentationProxy : public SecureHardwarePresentationProxy {
  public:
    JCSecureHardwarePresentationProxy();
    virtual ~JCSecureHardwarePresentationProxy();

    bool initialize(uint32_t sessionId, bool testCredential, const string& docType,
                    const vector<uint8_t>& encryptedCredentialKeys) override;

    size_t getHwChunkSize() override;

    bool shutdown() override;

    // Returns publicKeyCert (1st component) and signingKeyBlob (2nd component)
    optional<pair<vector<uint8_t>, vector<uint8_t>>> generateSigningKeyPair(const string& docType,
                                                                            time_t now) override;

    // Returns private key
    optional<vector<uint8_t>> createEphemeralKeyPair() override;

    optional<uint64_t> createAuthChallenge() override;

    bool startRetrieveEntries() override;

    bool setAuthToken(uint64_t challenge, uint64_t secureUserId, uint64_t authenticatorId,
                      int hardwareAuthenticatorType, uint64_t timeStamp, const vector<uint8_t>& mac,
                      uint64_t verificationTokenChallenge, uint64_t verificationTokenTimestamp,
                      int verificationTokenSecurityLevel,
                      const vector<uint8_t>& verificationTokenMac) override;

    bool pushReaderCert(const vector<uint8_t>& certX509) override;

    optional<bool> validateAccessControlProfile(int id, const vector<uint8_t>& readerCertificate,
                                                bool userAuthenticationRequired, int timeoutMillis,
                                                uint64_t secureUserId,
                                                const vector<uint8_t>& mac) override;

    bool validateRequestMessage(const vector<uint8_t>& sessionTranscript,
                                const vector<uint8_t>& requestMessage, int coseSignAlg,
                                const vector<uint8_t>& readerSignatureOfToBeSigned) override;

    bool calcMacKey(const vector<uint8_t>& sessionTranscript,
                    const vector<uint8_t>& readerEphemeralPublicKey,
                    const vector<uint8_t>& signingKeyBlob, const string& docType,
                    unsigned int numNamespacesWithValues,
                    size_t expectedProofOfProvisioningSize) override;

    AccessCheckResult startRetrieveEntryValue(
            const string& nameSpace, const string& name, unsigned int newNamespaceNumEntries,
            int32_t entrySize, const vector<int32_t>& accessControlProfileIds) override;

    optional<vector<uint8_t>> retrieveEntryValue(
            const vector<uint8_t>& encryptedContent, const string& nameSpace, const string& name,
            const vector<int32_t>& accessControlProfileIds) override;

    optional<vector<uint8_t>> finishRetrieval() override;

    optional<vector<uint8_t>> deleteCredential(const string& docType,
                                               const vector<uint8_t>& challenge,
                                               bool includeChallenge,
                                               size_t proofOfDeletionCborSize) override;

    optional<vector<uint8_t>> proveOwnership(const string& docType, bool testCredential,
                                             const vector<uint8_t>& challenge,
                                             size_t proofOfOwnershipCborSize) override;

  protected:
    // See docs for id_.
    //
    bool validateId(const string& callerName);

    // On the HAL side we keep track of the ID that was assigned to the libeic object
    // created in secure hardware. For every call into libeic we validate that this
    // identifier matches what is on the secure side. This is what the validateId()
    // method does.
    //
    uint32_t id_ = 0;
    AppletConnection mAppletConnection;
};

// Factory implementation.
//
class JCSecureHardwareProxyFactory : public SecureHardwareProxyFactory {
  public:
    JCSecureHardwareProxyFactory() {}
    virtual ~JCSecureHardwareProxyFactory() {}

    sp<SecureHardwareProxy> createHardwareProxy() override {
        return new JCSecureHardwareProxy();
    }

    sp<SecureHardwareProvisioningProxy> createProvisioningProxy() override {
        return new JCSecureHardwareProvisioningProxy();
    }

    sp<SecureHardwareSessionProxy> createSessionProxy() override {
        return new JCSecureHardwareSessionProxy();
    }

    sp<SecureHardwarePresentationProxy> createPresentationProxy() override {
        return new JCSecureHardwarePresentationProxy();
    }
};

}  // namespace android::hardware::identity

#endif  // ANDROID_HARDWARE_IDENTITY_JC_SECUREHARDWAREPROXY_H
