//
// @testable import CertificateSigningRequestSwift
import CertificateSigningRequestSwift // Only testing public functions
import Foundation
//  CertificateSigningRequestSwiftTests.swift
//  CertificateSigningRequestSwiftTests
//
//  Created by Corey Baker on 11/7/16.
//  Copyright © 2016 One Degree Technologies. All rights reserved.
//

import XCTest

// NOTE: Testcases won't work when testing within framework. I believe this because an Application needs to have an entitlement to have Keychain access

class CertificateSigningRequestSwiftTests: XCTestCase {
    var publicKey: SecKey?
    var privateKey: SecKey?
    var keyBlockSize: Int?
    var publicKeyBits: Data?
    let keyAlgoorithm = KeyAlgorithm.ec(signatureType: .sha256)

    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }

    func testiOSKeyCreation(_ test: Bool = true) {
        // This is an example of a functional test case.
        if (publicKey != nil) && (privateKey != nil) && keyBlockSize != nil {
            // Keys only need to be created once, after they can be used over again
            return
        }

        let tagPublic = "com.testing.ioscsrswift.public"
        let tagPrivate = "com.testing.ioscsrswift.private"

        let publicKeyParameters: [String: AnyObject] = [
            String(kSecAttrIsPermanent): kCFBooleanTrue,
            String(kSecAttrApplicationTag): tagPublic as AnyObject,
            String(kSecAttrAccessible): kSecAttrAccessibleAlways
        ]

        var privateKeyParameters: [String: AnyObject] = [
            String(kSecAttrIsPermanent): kCFBooleanTrue,
            String(kSecAttrApplicationTag): tagPrivate as AnyObject,
            String(kSecAttrAccessible): kSecAttrAccessibleAlways
        ]

        #if !arch(i386) && !arch(x86_64)
            // This only works for Secure Enclave consistign of 256 bit key, note, the signatureType is irrelavent for this check
            if keyAlgorithm.type == KeyAlgorithm.ec(signatureType: .sha1).type {
                let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                             kSecAttrAccessibleAlwaysThisDeviceOnly,
                                                             .privateKeyUsage,
                                                             nil)! // Ignore error

                privateKeyParameters[String(kSecAttrAccessControl)] = access
            }
        #endif

        // Define what type of keys to be generated here
        var parameters: [String: AnyObject] = [
            String(kSecReturnRef): kCFBooleanTrue,
            kSecPublicKeyAttrs as String: publicKeyParameters as AnyObject,
            kSecPrivateKeyAttrs as String: privateKeyParameters as AnyObject
        ]

        parameters[String(kSecAttrKeySizeInBits)] = keyAlgoorithm.availableKeySizes.last! as AnyObject

        if #available(iOS 10, *) {
            parameters[String(kSecAttrKeyType)] = keyAlgoorithm.secKeyAttrType
        } else {
            // Fallback on earlier versions
            parameters[String(kSecAttrKeyType)] = keyAlgoorithm.secKeyAttrTypeiOS9
        }

        #if !arch(i386) && !arch(x86_64)

            // iOS only allows EC 256 keys to be secured in enclave. This will attempt to allow any EC key in the enclave, assuming iOS will do it outside of the enclave if it doesn't like the key size, note: the signatureType is irrelavent for this check
            if keyAlgorithm.type == KeyAlgorithm.ec(signatureType: .sha1).type {
                parameters[String(kSecAttrTokenID)] = kSecAttrTokenIDSecureEnclave
            }

        #endif

        // Use Apple Security Framework to generate keys, save them to application keychain
        if #available(iOS 10.0, *) {
            var error: Unmanaged<CFError>?
            self.privateKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error)

            if self.privateKey == nil {
                XCTAssert(false, "Error occured: \(error!.takeRetainedValue() as Error), keys weren't created")
                return
            }

            // Get generated public key
            let query: [String: AnyObject] = [
                String(kSecClass): kSecClassKey,
                String(kSecAttrKeyType): keyAlgoorithm.secKeyAttrType,
                String(kSecAttrApplicationTag): tagPublic as AnyObject,
                String(kSecReturnRef): kCFBooleanTrue
            ]

            var publicKeyReturn: AnyObject?

            let result = SecItemCopyMatching(query as CFDictionary, &publicKeyReturn)

            if result != errSecSuccess {
                XCTAssert(false, "Error occured: \(result)")
                return
            }

            self.publicKey = publicKeyReturn as! SecKey?

        } else {
            // Fallback on earlier versions

            let result = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)

            if result != errSecSuccess {
                XCTAssert(false, "Error occured: \(result), keys weren't created")
                return
            }
        }

        print("Public and private key pair created")

        guard publicKey != nil else {
            if test {
                XCTAssert(false, "Error  in setUp(). PublicKey shouldn't be nil")
            }
            return
        }

        guard privateKey != nil else {
            if test {
                XCTAssert(false, "Error  in setUp(). PrivateKey shouldn't be nil")
            }
            return
        }

        // Set block size
        keyBlockSize = SecKeyGetBlockSize(publicKey!)

        // Ask keychain to provide the publicKey in bits
        var query: [String: AnyObject] = [
            String(kSecClass): kSecClassKey,
            String(kSecAttrApplicationTag): tagPublic as AnyObject,
            String(kSecReturnData): kCFBooleanTrue
        ]

        if #available(iOS 10, *) {
            query[String(kSecAttrKeyType)] = self.keyAlgoorithm.secKeyAttrType
        } else {
            // Fallback on earlier versions
            query[String(kSecAttrKeyType)] = keyAlgoorithm.secKeyAttrTypeiOS9
        }

        var tempPublicKeyBits: AnyObject?

        let result = SecItemCopyMatching(query as CFDictionary, &tempPublicKeyBits)

        switch result {
        case errSecSuccess:

            guard let keyBits = tempPublicKeyBits as? Data else {
                if test {
                    XCTAssert(false, "Error: couldn't cast publicKeyBits from AnyObject to Data")
                }
                return
            }

            publicKeyBits = keyBits

            if test {
                XCTAssert(true, "Pass")
            }

        default:
            if test {
                XCTAssert(false, "Error when retrieving publicKey in bits from the keychain: \(result)")
            }
        }
    }

    func testCSRStandardInitializer() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.

        // Ensure keys are available
        testiOSKeyCreation(false)

        if (publicKey != nil) && (privateKey != nil) && keyBlockSize != nil {
            // Keys only need to be created once, after they can be used over again
            XCTAssert(false, "Keys were not created")
            return
        }

        let csr = CertificateSigningRequest()

        guard let csrBuild = csr.build(publicKeyBits!, privateKey: privateKey!) else {
            XCTAssert(false, "Could not build CSR")
            return
        }

        guard let csrString = csrBuild.base64EncodedString(options: Data.Base64EncodingOptions(rawValue: 0)).addingPercentEncoding(withAllowedCharacters: CharacterSet.urlQueryAllowed) else {
            XCTAssert(false, "Could not encode CSR to string")
            return
        }

        if !csrString.isEmpty {
            XCTAssert(true, csrString)
        } else {
            XCTAssert(false, "Encoded CSR string was empty")
        }
    }

    func testPerformanceExample() {
        // This is an example of a performance test case.
        measure {
            // Put the code you want to measure the time of here.
        }
    }
}
