// https://github.com/Quick/Quick

import Quick
import Nimble
import CertificateSigningRequest

class TableOfContentsSpec: QuickSpec {
        
    override func spec() {
        
        describe("these will fail") {
            beforeEach {
                //Clear out App Keychain
                var query: [String:AnyObject] = [String(kSecClass): kSecClassKey]
                SecItemDelete(query as CFDictionary)

                query = [String(kSecClass): kSecClassKey]
                SecItemDelete(query as CFDictionary)
                
                query = [String(kSecClass): kSecClassCertificate]
                SecItemDelete(query as CFDictionary)
                
                query = [String(kSecClass): kSecClassIdentity]
                SecItemDelete(query as CFDictionary)
            }
            /*
            it("will eventually fail") {
                expect("time").toEventually( equal("done") )
            }*/
            
            context("these will pass") {
    
                it("create CSR using Eliptic Curve key size 256") {
                    let tagPrivate = "com.csr.private.ec"
                    let tagPublic = "com.csr.public.ec"
                    let keyAlgorithm = KeyAlgorithm.ec(signatureType: .sha256)
                    let sizeOfKey = keyAlgorithm.availableKeySizes.last!
                    
                    let (potentialPrivateKey,potentialPublicKey) = self.generateKeysAndStoreInKeychain(keyAlgorithm, keySize: sizeOfKey, tagPrivate: tagPrivate, tagPublic: tagPublic)
                    guard let privateKey = potentialPrivateKey,
                        let publicKey = potentialPublicKey else{
                            expect(potentialPrivateKey) != nil
                            expect(potentialPublicKey) != nil
                            return
                    }
                    
                    let (potentialPublicKeyBits, potentialPublicKeyBlockSize) = self.getPublicKeyBits(keyAlgorithm, publicKey: publicKey, tagPublic: tagPublic)
                    guard let publicKeyBits = potentialPublicKeyBits,
                        let _ = potentialPublicKeyBlockSize else{
                            expect(potentialPublicKeyBits) != nil
                            expect(potentialPublicKeyBlockSize) != nil
                            return
                    }
                    
                    //Initiale CSR
                    let csr = CertificateSigningRequest(commonName: "CertificateSigningRequest Test", organizationName: "Test", organizationUnitName: "Test", countryName: "US", stateOrProvinceName: "KY", localityName: "Test", keyAlgorithm: keyAlgorithm)
                    //Build the CSR
                    let csrBuild = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey, publicKey: publicKey)
                    if let csrRegular = csrBuild{
                        print("CSR string no header and footer")
                        print(csrRegular)
                    }
                    let csrBuild2 = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey, publicKey: publicKey)
                    if let csrWithHeaderFooter = csrBuild2{
                        print("CSR string with header and footer")
                        print(csrWithHeaderFooter)
                    }
                    expect(csrBuild?.count) > 0
                    expect(csrBuild2?.contains("BEGIN")) == true
                }

                it("create CSR using RSA key size 2048 with sha512") {
                    let tagPrivate = "com.csr.private.rsa"
                    let tagPublic = "com.csr.public.rsa"
                    let keyAlgorithm = KeyAlgorithm.rsa(signatureType: .sha512)
                    let sizeOfKey = keyAlgorithm.availableKeySizes.last!
                    
                    let (potentialPrivateKey,potentialPublicKey) = self.generateKeysAndStoreInKeychain(keyAlgorithm, keySize: sizeOfKey, tagPrivate: tagPrivate, tagPublic: tagPublic)
                    guard let privateKey = potentialPrivateKey,
                        let publicKey = potentialPublicKey else{
                            expect(potentialPrivateKey) != nil
                            expect(potentialPublicKey) != nil
                            return
                    }
                    
                    let (potentialPublicKeyBits, potentialPublicKeyBlockSize) = self.getPublicKeyBits(keyAlgorithm, publicKey: publicKey, tagPublic: tagPublic)
                    guard let publicKeyBits = potentialPublicKeyBits,
                        let _ = potentialPublicKeyBlockSize else{
                            expect(potentialPublicKeyBits) != nil
                            expect(potentialPublicKeyBlockSize) != nil
                            return
                    }
                    
                    //Initiale CSR
                    let csr = CertificateSigningRequest(commonName: "CertificateSigningRequest Test", organizationName: "Test", organizationUnitName: "Test", countryName: "US", stateOrProvinceName: "KY", localityName: "Test", keyAlgorithm: keyAlgorithm)
                    //Build the CSR
                    let csrBuild = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey)
                    if let csrRegular = csrBuild{
                        print("CSR string no header and footer")
                        print(csrRegular)
                    }
                    let csrBuild2 = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey)
                    if let csrWithHeaderFooter = csrBuild2{
                        print("CSR string with header and footer")
                        print(csrWithHeaderFooter)
                    }
                    expect(csrBuild?.count) > 0
                    expect(csrBuild2?.contains("BEGIN")) == true
                }
                
                it("create CSR using RSA key size 1024 with sha512") {
                    let tagPrivate = "com.csr.private.rsa1024"
                    let tagPublic = "com.csr.public.rsa1024"
                    let keyAlgorithm = KeyAlgorithm.rsa(signatureType: .sha512)
                    let sizeOfKey = keyAlgorithm.availableKeySizes[1]
                    
                    let (potentialPrivateKey,potentialPublicKey) = self.generateKeysAndStoreInKeychain(keyAlgorithm, keySize: sizeOfKey, tagPrivate: tagPrivate, tagPublic: tagPublic)
                    guard let privateKey = potentialPrivateKey,
                        let publicKey = potentialPublicKey else{
                            expect(potentialPrivateKey) != nil
                            expect(potentialPublicKey) != nil
                            return
                    }
                    
                    let (potentialPublicKeyBits, potentialPublicKeyBlockSize) = self.getPublicKeyBits(keyAlgorithm, publicKey: publicKey, tagPublic: tagPublic)
                    guard let publicKeyBits = potentialPublicKeyBits,
                        let _ = potentialPublicKeyBlockSize else{
                            expect(potentialPublicKeyBits) != nil
                            expect(potentialPublicKeyBlockSize) != nil
                            return
                    }
                    
                    //Initiale CSR
                    let csr = CertificateSigningRequest(commonName: "CertificateSigningRequest Test", organizationName: "Test", organizationUnitName: "Test", countryName: "US", stateOrProvinceName: "KY", localityName: "Test", keyAlgorithm: keyAlgorithm)
                    //Build the CSR
                    let csrBuild = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey)
                    if let csrRegular = csrBuild{
                        print("CSR string no header and footer")
                        print(csrRegular)
                    }
                    let csrBuild2 = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey)
                    if let csrWithHeaderFooter = csrBuild2{
                        print("CSR string with header and footer")
                        print(csrWithHeaderFooter)
                    }
                    expect(csrBuild?.count) > 0
                    expect(csrBuild2?.contains("BEGIN")) == true
                }
                
                it("create CSR using RSA key size 512 with sha512") {
                    let tagPrivate = "com.csr.private.rsa512"
                    let tagPublic = "com.csr.public.rsa512"
                    let keyAlgorithm = KeyAlgorithm.rsa(signatureType: .sha512)
                    let sizeOfKey = keyAlgorithm.availableKeySizes[0]
                    
                    let (potentialPrivateKey,potentialPublicKey) = self.generateKeysAndStoreInKeychain(keyAlgorithm, keySize: sizeOfKey, tagPrivate: tagPrivate, tagPublic: tagPublic)
                    guard let privateKey = potentialPrivateKey,
                        let publicKey = potentialPublicKey else{
                            expect(potentialPrivateKey) != nil
                            expect(potentialPublicKey) != nil
                            return
                    }
                    
                    let (potentialPublicKeyBits, potentialPublicKeyBlockSize) = self.getPublicKeyBits(keyAlgorithm, publicKey: publicKey, tagPublic: tagPublic)
                    guard let publicKeyBits = potentialPublicKeyBits,
                        let _ = potentialPublicKeyBlockSize else{
                            expect(potentialPublicKeyBits) != nil
                            expect(potentialPublicKeyBlockSize) != nil
                            return
                    }
                    
                    //Initiale CSR
                    let csr = CertificateSigningRequest(commonName: "CertificateSigningRequest Test", organizationName: "Test", organizationUnitName: "Test", countryName: "US", stateOrProvinceName: "KY", localityName: "Test", keyAlgorithm: keyAlgorithm)
                    //Build the CSR
                    let csrBuild = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey)
                    if let csrRegular = csrBuild{
                        print("CSR string no header and footer")
                        print(csrRegular)
                    }
                    let csrBuild2 = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey)
                    if let csrWithHeaderFooter = csrBuild2{
                        print("CSR string with header and footer")
                        print(csrWithHeaderFooter)
                    }
                    expect(csrBuild?.count) > 0
                    expect(csrBuild2?.contains("BEGIN")) == true
                }
                
                it("create CSR using RSA key size 2048 with sha256") {
                    let tagPrivate = "com.csr.private.rsa256"
                    let tagPublic = "com.csr.public.rsa256"
                    let keyAlgorithm = KeyAlgorithm.rsa(signatureType: .sha256)
                    let sizeOfKey = keyAlgorithm.availableKeySizes.last!
                    
                    let (potentialPrivateKey,potentialPublicKey) = self.generateKeysAndStoreInKeychain(keyAlgorithm, keySize: sizeOfKey, tagPrivate: tagPrivate, tagPublic: tagPublic)
                    guard let privateKey = potentialPrivateKey,
                        let publicKey = potentialPublicKey else{
                            expect(potentialPrivateKey) != nil
                            expect(potentialPublicKey) != nil
                            return
                    }
                    
                    let (potentialPublicKeyBits, potentialPublicKeyBlockSize) = self.getPublicKeyBits(keyAlgorithm, publicKey: publicKey, tagPublic: tagPublic)
                    guard let publicKeyBits = potentialPublicKeyBits,
                        let _ = potentialPublicKeyBlockSize else{
                            expect(potentialPublicKeyBits) != nil
                            expect(potentialPublicKeyBlockSize) != nil
                            return
                    }
                    
                    //Initiale CSR
                    let csr = CertificateSigningRequest(commonName: "CertificateSigningRequest Test", organizationName: "Test", organizationUnitName: "Test", countryName: "US", stateOrProvinceName: "KY", localityName: "Test", keyAlgorithm: keyAlgorithm)
                    //Build the CSR
                    let csrBuild = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey)
                    if let csrRegular = csrBuild{
                        print("CSR string no header and footer")
                        print(csrRegular)
                    }
                    let csrBuild2 = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey)
                    if let csrWithHeaderFooter = csrBuild2{
                        print("CSR string with header and footer")
                        print(csrWithHeaderFooter)
                    }
                    expect(csrBuild?.count) > 0
                    expect(csrBuild2?.contains("BEGIN")) == true
                }
                
                it("create CSR using RSA key size 2048 with sha1") {
                    let tagPrivate = "com.csr.private.rsa1"
                    let tagPublic = "com.csr.public.rsa1"
                    let keyAlgorithm = KeyAlgorithm.rsa(signatureType: .sha1)
                    let sizeOfKey = keyAlgorithm.availableKeySizes.last!
                    
                    let (potentialPrivateKey,potentialPublicKey) = self.generateKeysAndStoreInKeychain(keyAlgorithm, keySize: sizeOfKey, tagPrivate: tagPrivate, tagPublic: tagPublic)
                    guard let privateKey = potentialPrivateKey,
                        let publicKey = potentialPublicKey else{
                            expect(potentialPrivateKey) != nil
                            expect(potentialPublicKey) != nil
                            return
                    }
                    
                    let (potentialPublicKeyBits, potentialPublicKeyBlockSize) = self.getPublicKeyBits(keyAlgorithm, publicKey: publicKey, tagPublic: tagPublic)
                    guard let publicKeyBits = potentialPublicKeyBits,
                        let _ = potentialPublicKeyBlockSize else{
                            expect(potentialPublicKeyBits) != nil
                            expect(potentialPublicKeyBlockSize) != nil
                            return
                    }
                    
                    //Initiale CSR
                    let csr = CertificateSigningRequest(commonName: "CertificateSigningRequest Test", organizationName: "Test", organizationUnitName: "Test", countryName: "US", stateOrProvinceName: "KY", localityName: "Test", keyAlgorithm: keyAlgorithm)
                    //Build the CSR
                    let csrBuild = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey)
                    if let csrRegular = csrBuild{
                        print("CSR string no header and footer")
                        print(csrRegular)
                    }
                    let csrBuild2 = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey)
                    if let csrWithHeaderFooter = csrBuild2{
                        print("CSR string with header and footer")
                        print(csrWithHeaderFooter)
                    }
                    expect(csrBuild?.count) > 0
                    expect(csrBuild2?.contains("BEGIN")) == true
                }
                
                /*
                it("will eventually pass") {
                    var time = "passing"

                    DispatchQueue.main.async {
                        time = "done"
                    }

                    waitUntil { done in
                        Thread.sleep(forTimeInterval: 0.5)
                        expect(time) == "done"

                        done()
                    }
                }*/
            }
        }
    }
    
    func generateKeysAndStoreInKeychain(_ algorithm: KeyAlgorithm, keySize: Int, tagPrivate: String, tagPublic: String)->(SecKey?,SecKey?){
        let publicKeyParameters: [String: AnyObject] = [
            String(kSecAttrIsPermanent): kCFBooleanTrue,
            String(kSecAttrApplicationTag): tagPublic as AnyObject,
            String(kSecAttrAccessible): kSecAttrAccessibleAfterFirstUnlock
        ]
        
        var privateKeyParameters: [String: AnyObject] = [
            String(kSecAttrIsPermanent): kCFBooleanTrue,
            String(kSecAttrApplicationTag): tagPrivate as AnyObject,
            String(kSecAttrAccessible): kSecAttrAccessibleAfterFirstUnlock
        ]
        
        #if !targetEnvironment(simulator)
            //This only works for Secure Enclave consistign of 256 bit key, note, the signatureType is irrelavent for this check
            if algorithm.type == KeyAlgorithm.ec(signatureType: .sha1).type{
                let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                             kSecAttrAccessibleAfterFirstUnlock,
                                                             .privateKeyUsage,
                                                             nil)!   // Ignore error
                
                privateKeyParameters[String(kSecAttrAccessControl)] = access
            }
        #endif
        
        //Define what type of keys to be generated here
        var parameters: [String: AnyObject] = [
            String(kSecAttrKeyType): algorithm.secKeyAttrType,
            String(kSecAttrKeySizeInBits): keySize as AnyObject,
            String(kSecReturnRef): kCFBooleanTrue,
            String(kSecPublicKeyAttrs): publicKeyParameters as AnyObject,
            String(kSecPrivateKeyAttrs): privateKeyParameters as AnyObject,
        ]
        
        #if !targetEnvironment(simulator)
            //iOS only allows EC 256 keys to be secured in enclave. This will attempt to allow any EC key in the enclave, assuming iOS will do it outside of the enclave if it doesn't like the key size, note: the signatureType is irrelavent for this check
            if algorithm.type == KeyAlgorithm.ec(signatureType: .sha1).type{
                parameters[String(kSecAttrTokenID)] = kSecAttrTokenIDSecureEnclave
            }
        #endif
        
        //Use Apple Security Framework to generate keys, save them to application keychain
        var error: Unmanaged<CFError>?
        let privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error)
        if privateKey == nil{
            print("Error creating keys occured: \(error!.takeRetainedValue() as Error), keys weren't created")
            return (nil,nil)
        }
        
        //Get generated public key
        let query: [String: AnyObject] = [
            String(kSecClass): kSecClassKey,
            String(kSecAttrKeyType): algorithm.secKeyAttrType,
            String(kSecAttrApplicationTag): tagPublic as AnyObject,
            String(kSecReturnRef): kCFBooleanTrue
        ]
        var publicKeyReturn:AnyObject?
        let result = SecItemCopyMatching(query as CFDictionary, &publicKeyReturn)
        if result != errSecSuccess{
            print("Error getting publicKey fron keychain occured: \(result)")
            return (privateKey,nil)
        }
        let publicKey = publicKeyReturn as! SecKey?
        return (privateKey,publicKey)
    }
    
    func getPublicKeyBits(_ algorithm: KeyAlgorithm, publicKey: SecKey, tagPublic: String)->(Data?,Int?) {
        //Set block size
        let keyBlockSize = SecKeyGetBlockSize(publicKey)
        //Ask keychain to provide the publicKey in bits
        let query: [String: AnyObject] = [
            String(kSecClass): kSecClassKey,
            String(kSecAttrKeyType): algorithm.secKeyAttrType,
            String(kSecAttrApplicationTag): tagPublic as AnyObject,
            String(kSecReturnData): kCFBooleanTrue
        ]
        var tempPublicKeyBits:AnyObject?
        var _ = SecItemCopyMatching(query as CFDictionary, &tempPublicKeyBits)
        guard let keyBits = tempPublicKeyBits as? Data else {
            return (nil,nil)
        }
        return (keyBits,keyBlockSize)
    }
    
}
