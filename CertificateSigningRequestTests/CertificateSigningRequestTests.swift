//
//  CertificateSigningRequestSwiftTests.swift
//  CertificateSigningRequestSwiftTests
//
//  Created by Corey Baker on 11/7/16.
//  Copyright © 2016 Network Reconnaissance Lab. All rights reserved.
//

import XCTest
import Foundation
//@testable import CertificateSigningRequestSwift
import CertificateSigningRequest //Only testing public functions


class CertificateSigningRequestSwiftTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
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
    
    func testCreateCSRwithECKey(){
        let tagPrivate = "com.csr.private.ec"
        let tagPublic = "com.csr.public.ec"
        let keyAlgorithm = KeyAlgorithm.ec(signatureType: .sha256)
        let sizeOfKey = keyAlgorithm.availableKeySizes.last!
        
        let (potentialPrivateKey,potentialPublicKey) = self.generateKeysAndStoreInKeychain(keyAlgorithm, keySize: sizeOfKey, tagPrivate: tagPrivate, tagPublic: tagPublic)
        guard let privateKey = potentialPrivateKey,
            let publicKey = potentialPublicKey else{
                XCTAssertNotNil(potentialPrivateKey, "Private key not generated")
                XCTAssertNotNil(potentialPublicKey, "Public key not generated")
                return
        }
        
        let (potentialPublicKeyBits, potentialPublicKeyBlockSize) = self.getPublicKeyBits(keyAlgorithm, publicKey: publicKey, tagPublic: tagPublic)
        guard let publicKeyBits = potentialPublicKeyBits,
            let _ = potentialPublicKeyBlockSize else{
                XCTAssertNotNil(potentialPublicKeyBits, "Private key bits not generated")
                XCTAssertNotNil(potentialPublicKeyBlockSize, "Public key block size not generated")
                return
        }
        
        //Initiale CSR
        let csr = CertificateSigningRequest(commonName: "CertificateSigningRequest Test", organizationName: "Test", organizationUnitName: "Test", countryName: "US", stateOrProvinceName: "KY", localityName: "Test", keyAlgorithm: keyAlgorithm)
        //Build the CSR
        let csrBuild = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey, publicKey: publicKey)
        let csrBuild2 = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey, publicKey: publicKey)
        if let csrRegular = csrBuild{
            print("CSR string no header and footer")
            print(csrRegular)
            XCTAssertGreaterThan(csrBuild!.count,0, "CSR contains no data")
        }else{
            XCTAssertNotNil(csrBuild, "CSR with header not generated")
        }
        if let csrWithHeaderFooter = csrBuild2{
            print("CSR string with header and footer")
            print(csrWithHeaderFooter)
            XCTAssertTrue(csrBuild2!.contains("BEGIN"),"CSR string builder isn't complete")
        }else{
            XCTAssertNotNil(csrBuild2, "CSR with header not generated")
        }
    }
    
    func testCreateCSRwithRSA2048KeySha512(){
        let tagPrivate = "com.csr.private.rsa"
        let tagPublic = "com.csr.public.rsa"
        let keyAlgorithm = KeyAlgorithm.rsa(signatureType: .sha512)
        let sizeOfKey = keyAlgorithm.availableKeySizes.last!
        
        let (potentialPrivateKey,potentialPublicKey) = self.generateKeysAndStoreInKeychain(keyAlgorithm, keySize: sizeOfKey, tagPrivate: tagPrivate, tagPublic: tagPublic)
        guard let privateKey = potentialPrivateKey,
            let publicKey = potentialPublicKey else{
                XCTAssertNotNil(potentialPrivateKey, "Private key not generated")
                XCTAssertNotNil(potentialPublicKey, "Public key not generated")
                return
        }
        
        let (potentialPublicKeyBits, potentialPublicKeyBlockSize) = self.getPublicKeyBits(keyAlgorithm, publicKey: publicKey, tagPublic: tagPublic)
        guard let publicKeyBits = potentialPublicKeyBits,
            let _ = potentialPublicKeyBlockSize else{
                XCTAssertNotNil(potentialPublicKeyBits, "Private key bits not generated")
                XCTAssertNotNil(potentialPublicKeyBlockSize, "Public key block size not generated")
                return
        }
        
        //Initiale CSR
        let csr = CertificateSigningRequest(commonName: "CertificateSigningRequest Test", organizationName: "Test", organizationUnitName: "Test", countryName: "US", stateOrProvinceName: "KY", localityName: "Test", keyAlgorithm: keyAlgorithm)
        //Build the CSR
        let csrBuild = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey)
        let csrBuild2 = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey)
        if let csrRegular = csrBuild{
            print("CSR string no header and footer")
            print(csrRegular)
            XCTAssertGreaterThan(csrBuild!.count,0, "CSR contains no data")
        }else{
            XCTAssertNotNil(csrBuild, "CSR with header not generated")
        }
        if let csrWithHeaderFooter = csrBuild2{
            print("CSR string with header and footer")
            print(csrWithHeaderFooter)
            XCTAssertTrue(csrBuild2!.contains("BEGIN"),"CSR string builder isn't complete")
        }else{
            XCTAssertNotNil(csrBuild2, "CSR with header not generated")
        }
    }
    
    func testCreateCSRwithRSA2048KeySha256(){
        let tagPrivate = "com.csr.private.rsa256"
        let tagPublic = "com.csr.public.rsa256"
        let keyAlgorithm = KeyAlgorithm.rsa(signatureType: .sha256)
        let sizeOfKey = keyAlgorithm.availableKeySizes.last!
        
        let (potentialPrivateKey,potentialPublicKey) = self.generateKeysAndStoreInKeychain(keyAlgorithm, keySize: sizeOfKey, tagPrivate: tagPrivate, tagPublic: tagPublic)
        guard let privateKey = potentialPrivateKey,
            let publicKey = potentialPublicKey else{
                XCTAssertNotNil(potentialPrivateKey, "Private key not generated")
                XCTAssertNotNil(potentialPublicKey, "Public key not generated")
                return
        }
        
        let (potentialPublicKeyBits, potentialPublicKeyBlockSize) = self.getPublicKeyBits(keyAlgorithm, publicKey: publicKey, tagPublic: tagPublic)
        guard let publicKeyBits = potentialPublicKeyBits,
            let _ = potentialPublicKeyBlockSize else{
                XCTAssertNotNil(potentialPublicKeyBits, "Private key bits not generated")
                XCTAssertNotNil(potentialPublicKeyBlockSize, "Public key block size not generated")
                return
        }
        
        //Initiale CSR
        let csr = CertificateSigningRequest(commonName: "CertificateSigningRequest Test", organizationName: "Test", organizationUnitName: "Test", countryName: "US", stateOrProvinceName: "KY", localityName: "Test", keyAlgorithm: keyAlgorithm)
        //Build the CSR
        let csrBuild = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey)
        let csrBuild2 = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey)
        if let csrRegular = csrBuild{
            print("CSR string no header and footer")
            print(csrRegular)
            XCTAssertGreaterThan(csrBuild!.count,0, "CSR contains no data")
        }else{
            XCTAssertNotNil(csrBuild, "CSR with header not generated")
        }
        if let csrWithHeaderFooter = csrBuild2{
            print("CSR string with header and footer")
            print(csrWithHeaderFooter)
            XCTAssertTrue(csrBuild2!.contains("BEGIN"),"CSR string builder isn't complete")
        }else{
            XCTAssertNotNil(csrBuild2, "CSR with header not generated")
        }
    }
    
    func testCreateCSRwithRSA2048KeySha1(){
        let tagPrivate = "com.csr.private.rsa1"
        let tagPublic = "com.csr.public.rsa1"
        let keyAlgorithm = KeyAlgorithm.rsa(signatureType: .sha1)
        let sizeOfKey = keyAlgorithm.availableKeySizes.last!
        
        let (potentialPrivateKey,potentialPublicKey) = self.generateKeysAndStoreInKeychain(keyAlgorithm, keySize: sizeOfKey, tagPrivate: tagPrivate, tagPublic: tagPublic)
        guard let privateKey = potentialPrivateKey,
            let publicKey = potentialPublicKey else{
                XCTAssertNotNil(potentialPrivateKey, "Private key not generated")
                XCTAssertNotNil(potentialPublicKey, "Public key not generated")
                return
        }
        
        let (potentialPublicKeyBits, potentialPublicKeyBlockSize) = self.getPublicKeyBits(keyAlgorithm, publicKey: publicKey, tagPublic: tagPublic)
        guard let publicKeyBits = potentialPublicKeyBits,
            let _ = potentialPublicKeyBlockSize else{
                XCTAssertNotNil(potentialPublicKeyBits, "Private key bits not generated")
                XCTAssertNotNil(potentialPublicKeyBlockSize, "Public key block size not generated")
                return
        }
        
        //Initiale CSR
        let csr = CertificateSigningRequest(commonName: "CertificateSigningRequest Test", organizationName: "Test", organizationUnitName: "Test", countryName: "US", stateOrProvinceName: "KY", localityName: "Test", keyAlgorithm: keyAlgorithm)
        //Build the CSR
        let csrBuild = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey)
        let csrBuild2 = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey)
        if let csrRegular = csrBuild{
            print("CSR string no header and footer")
            print(csrRegular)
            XCTAssertGreaterThan(csrBuild!.count,0, "CSR contains no data")
        }else{
            XCTAssertNotNil(csrBuild, "CSR with header not generated")
        }
        if let csrWithHeaderFooter = csrBuild2{
            print("CSR string with header and footer")
            print(csrWithHeaderFooter)
            XCTAssertTrue(csrBuild2!.contains("BEGIN"),"CSR string builder isn't complete")
        }else{
            XCTAssertNotNil(csrBuild2, "CSR with header not generated")
        }
    }
    
    func testCreateCSRwithRSA1024KeySha512(){
        let tagPrivate = "com.csr.private.rsa1024"
        let tagPublic = "com.csr.public.rsa1024"
        let keyAlgorithm = KeyAlgorithm.rsa(signatureType: .sha512)
        let sizeOfKey = keyAlgorithm.availableKeySizes[1]
        
        let (potentialPrivateKey,potentialPublicKey) = self.generateKeysAndStoreInKeychain(keyAlgorithm, keySize: sizeOfKey, tagPrivate: tagPrivate, tagPublic: tagPublic)
        guard let privateKey = potentialPrivateKey,
            let publicKey = potentialPublicKey else{
                XCTAssertNotNil(potentialPrivateKey, "Private key not generated")
                XCTAssertNotNil(potentialPublicKey, "Public key not generated")
                return
        }
        
        let (potentialPublicKeyBits, potentialPublicKeyBlockSize) = self.getPublicKeyBits(keyAlgorithm, publicKey: publicKey, tagPublic: tagPublic)
        guard let publicKeyBits = potentialPublicKeyBits,
            let _ = potentialPublicKeyBlockSize else{
                XCTAssertNotNil(potentialPublicKeyBits, "Private key bits not generated")
                XCTAssertNotNil(potentialPublicKeyBlockSize, "Public key block size not generated")
                return
        }
        
        //Initiale CSR
        let csr = CertificateSigningRequest(commonName: "CertificateSigningRequest Test", organizationName: "Test", organizationUnitName: "Test", countryName: "US", stateOrProvinceName: "KY", localityName: "Test", keyAlgorithm: keyAlgorithm)
        //Build the CSR
        let csrBuild = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey)
        let csrBuild2 = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey)
        if let csrRegular = csrBuild{
            print("CSR string no header and footer")
            print(csrRegular)
            XCTAssertGreaterThan(csrBuild!.count,0, "CSR contains no data")
        }else{
            XCTAssertNotNil(csrBuild, "CSR with header not generated")
        }
        if let csrWithHeaderFooter = csrBuild2{
            print("CSR string with header and footer")
            print(csrWithHeaderFooter)
            XCTAssertTrue(csrBuild2!.contains("BEGIN"),"CSR string builder isn't complete")
        }else{
            XCTAssertNotNil(csrBuild2, "CSR with header not generated")
        }
    }
    
    func testCreateCSRwithRSA1024KeySha256(){
        let tagPrivate = "com.csr.private.rsa1024sha256"
        let tagPublic = "com.csr.public.rsa1024sha256"
        let keyAlgorithm = KeyAlgorithm.rsa(signatureType: .sha256)
        let sizeOfKey = keyAlgorithm.availableKeySizes[1]
        
        let (potentialPrivateKey,potentialPublicKey) = self.generateKeysAndStoreInKeychain(keyAlgorithm, keySize: sizeOfKey, tagPrivate: tagPrivate, tagPublic: tagPublic)
        guard let privateKey = potentialPrivateKey,
            let publicKey = potentialPublicKey else{
                XCTAssertNotNil(potentialPrivateKey, "Private key not generated")
                XCTAssertNotNil(potentialPublicKey, "Public key not generated")
                return
        }
        
        let (potentialPublicKeyBits, potentialPublicKeyBlockSize) = self.getPublicKeyBits(keyAlgorithm, publicKey: publicKey, tagPublic: tagPublic)
        guard let publicKeyBits = potentialPublicKeyBits,
            let _ = potentialPublicKeyBlockSize else{
                XCTAssertNotNil(potentialPublicKeyBits, "Private key bits not generated")
                XCTAssertNotNil(potentialPublicKeyBlockSize, "Public key block size not generated")
                return
        }
        
        //Initiale CSR
        let csr = CertificateSigningRequest(commonName: "CertificateSigningRequest Test", organizationName: "Test", organizationUnitName: "Test", countryName: "US", stateOrProvinceName: "KY", localityName: "Test", keyAlgorithm: keyAlgorithm)
        //Build the CSR
        let csrBuild = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey)
        let csrBuild2 = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey)
        if let csrRegular = csrBuild{
            print("CSR string no header and footer")
            print(csrRegular)
            XCTAssertGreaterThan(csrBuild!.count,0, "CSR contains no data")
        }else{
            XCTAssertNotNil(csrBuild, "CSR with header not generated")
        }
        if let csrWithHeaderFooter = csrBuild2{
            print("CSR string with header and footer")
            print(csrWithHeaderFooter)
            XCTAssertTrue(csrBuild2!.contains("BEGIN"),"CSR string builder isn't complete")
        }else{
            XCTAssertNotNil(csrBuild2, "CSR with header not generated")
        }
    }
    
    func testCreateCSRwithRSA1024KeySha1(){
        let tagPrivate = "com.csr.private.rsa1024sha1"
        let tagPublic = "com.csr.public.rsa1024sha1"
        let keyAlgorithm = KeyAlgorithm.rsa(signatureType: .sha1)
        let sizeOfKey = keyAlgorithm.availableKeySizes[1]
        
        let (potentialPrivateKey,potentialPublicKey) = self.generateKeysAndStoreInKeychain(keyAlgorithm, keySize: sizeOfKey, tagPrivate: tagPrivate, tagPublic: tagPublic)
        guard let privateKey = potentialPrivateKey,
            let publicKey = potentialPublicKey else{
                XCTAssertNotNil(potentialPrivateKey, "Private key not generated")
                XCTAssertNotNil(potentialPublicKey, "Public key not generated")
                return
        }
        
        let (potentialPublicKeyBits, potentialPublicKeyBlockSize) = self.getPublicKeyBits(keyAlgorithm, publicKey: publicKey, tagPublic: tagPublic)
        guard let publicKeyBits = potentialPublicKeyBits,
            let _ = potentialPublicKeyBlockSize else{
                XCTAssertNotNil(potentialPublicKeyBits, "Private key bits not generated")
                XCTAssertNotNil(potentialPublicKeyBlockSize, "Public key block size not generated")
                return
        }
        
        //Initiale CSR
        let csr = CertificateSigningRequest(commonName: "CertificateSigningRequest Test", organizationName: "Test", organizationUnitName: "Test", countryName: "US", stateOrProvinceName: "KY", localityName: "Test", keyAlgorithm: keyAlgorithm)
        //Build the CSR
        let csrBuild = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey)
        let csrBuild2 = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey)
        if let csrRegular = csrBuild{
            print("CSR string no header and footer")
            print(csrRegular)
            XCTAssertGreaterThan(csrBuild!.count,0, "CSR contains no data")
        }else{
            XCTAssertNotNil(csrBuild, "CSR with header not generated")
        }
        if let csrWithHeaderFooter = csrBuild2{
            print("CSR string with header and footer")
            print(csrWithHeaderFooter)
            XCTAssertTrue(csrBuild2!.contains("BEGIN"),"CSR string builder isn't complete")
        }else{
            XCTAssertNotNil(csrBuild2, "CSR with header not generated")
        }
    }
    
    func testCreateCSRwithRSA512KeySha512(){
        let tagPrivate = "com.csr.private.rsa512sha512"
        let tagPublic = "com.csr.public.rsa512sha512"
        let keyAlgorithm = KeyAlgorithm.rsa(signatureType: .sha512)
        let sizeOfKey = keyAlgorithm.availableKeySizes[0]
        
        let (potentialPrivateKey,potentialPublicKey) = self.generateKeysAndStoreInKeychain(keyAlgorithm, keySize: sizeOfKey, tagPrivate: tagPrivate, tagPublic: tagPublic)
        guard let privateKey = potentialPrivateKey,
            let publicKey = potentialPublicKey else{
                XCTAssertNotNil(potentialPrivateKey, "Private key not generated")
                XCTAssertNotNil(potentialPublicKey, "Public key not generated")
                return
        }
        
        let (potentialPublicKeyBits, potentialPublicKeyBlockSize) = self.getPublicKeyBits(keyAlgorithm, publicKey: publicKey, tagPublic: tagPublic)
        guard let publicKeyBits = potentialPublicKeyBits,
            let _ = potentialPublicKeyBlockSize else{
                XCTAssertNotNil(potentialPublicKeyBits, "Private key bits not generated")
                XCTAssertNotNil(potentialPublicKeyBlockSize, "Public key block size not generated")
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
        XCTAssertNil(csrBuild, "CSR should fail to generate anything")
        XCTAssertNil(csrBuild2,"CSR should fail to generate anything")
    }
    
    func testCreateCSRwithRSA512KeySha256(){
        let tagPrivate = "com.csr.private.rsa512"
        let tagPublic = "com.csr.public.rsa512"
        let keyAlgorithm = KeyAlgorithm.rsa(signatureType: .sha256)
        let sizeOfKey = keyAlgorithm.availableKeySizes[0]
        
        let (potentialPrivateKey,potentialPublicKey) = self.generateKeysAndStoreInKeychain(keyAlgorithm, keySize: sizeOfKey, tagPrivate: tagPrivate, tagPublic: tagPublic)
        guard let privateKey = potentialPrivateKey,
            let publicKey = potentialPublicKey else{
                XCTAssertNotNil(potentialPrivateKey, "Private key not generated")
                XCTAssertNotNil(potentialPublicKey, "Public key not generated")
                return
        }
        
        let (potentialPublicKeyBits, potentialPublicKeyBlockSize) = self.getPublicKeyBits(keyAlgorithm, publicKey: publicKey, tagPublic: tagPublic)
        guard let publicKeyBits = potentialPublicKeyBits,
            let _ = potentialPublicKeyBlockSize else{
                XCTAssertNotNil(potentialPublicKeyBits, "Private key bits not generated")
                XCTAssertNotNil(potentialPublicKeyBlockSize, "Public key block size not generated")
                return
        }
        
        //Initiale CSR
        let csr = CertificateSigningRequest(commonName: "CertificateSigningRequest Test", organizationName: "Test", organizationUnitName: "Test", countryName: "US", stateOrProvinceName: "KY", localityName: "Test", keyAlgorithm: keyAlgorithm)
        //Build the CSR
        let csrBuild = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey)
        let csrBuild2 = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey)
        if let csrRegular = csrBuild{
            print("CSR string no header and footer")
            print(csrRegular)
            XCTAssertGreaterThan(csrBuild!.count,0, "CSR contains no data")
        }else{
            XCTAssertNotNil(csrBuild, "CSR with header not generated")
        }
        if let csrWithHeaderFooter = csrBuild2{
            print("CSR string with header and footer")
            print(csrWithHeaderFooter)
            XCTAssertTrue(csrBuild2!.contains("BEGIN"),"CSR string builder isn't complete")
        }else{
            XCTAssertNotNil(csrBuild2, "CSR with header not generated")
        }
    }
    
    func testCreateCSRwithRSA512KeySha1(){
        let tagPrivate = "com.csr.private.rsa512sha1"
        let tagPublic = "com.csr.public.rsa512sha1"
        let keyAlgorithm = KeyAlgorithm.rsa(signatureType: .sha1)
        let sizeOfKey = keyAlgorithm.availableKeySizes[0]
        
        let (potentialPrivateKey,potentialPublicKey) = self.generateKeysAndStoreInKeychain(keyAlgorithm, keySize: sizeOfKey, tagPrivate: tagPrivate, tagPublic: tagPublic)
        guard let privateKey = potentialPrivateKey,
            let publicKey = potentialPublicKey else{
                XCTAssertNotNil(potentialPrivateKey, "Private key not generated")
                XCTAssertNotNil(potentialPublicKey, "Public key not generated")
                return
        }
        
        let (potentialPublicKeyBits, potentialPublicKeyBlockSize) = self.getPublicKeyBits(keyAlgorithm, publicKey: publicKey, tagPublic: tagPublic)
        guard let publicKeyBits = potentialPublicKeyBits,
            let _ = potentialPublicKeyBlockSize else{
                XCTAssertNotNil(potentialPublicKeyBits, "Private key bits not generated")
                XCTAssertNotNil(potentialPublicKeyBlockSize, "Public key block size not generated")
                return
        }
        
        //Initiale CSR
        let csr = CertificateSigningRequest(commonName: "CertificateSigningRequest Test", organizationName: "Test", organizationUnitName: "Test", countryName: "US", stateOrProvinceName: "KY", localityName: "Test", keyAlgorithm: keyAlgorithm)
        //Build the CSR
        let csrBuild = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey)
        let csrBuild2 = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey)
        if let csrRegular = csrBuild{
            print("CSR string no header and footer")
            print(csrRegular)
            XCTAssertGreaterThan(csrBuild!.count,0, "CSR contains no data")
        }else{
            XCTAssertNotNil(csrBuild, "CSR with header not generated")
        }
        if let csrWithHeaderFooter = csrBuild2{
            print("CSR string with header and footer")
            print(csrWithHeaderFooter)
            XCTAssertTrue(csrBuild2!.contains("BEGIN"),"CSR string builder isn't complete")
        }else{
            XCTAssertNotNil(csrBuild2, "CSR with header not generated")
        }
    }
    /*
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }
    */
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
