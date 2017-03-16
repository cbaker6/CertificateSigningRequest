//
//  iOSCSRSwiftTests.swift
//  iOSCSRSwift
//
//  Created by Corey Baker on 11/7/16.
//  Copyright © 2016 One Degree Technologies. All rights reserved.
//

import XCTest
//@testable import iOSCSRSwift
import iOSCSRSwift //Only testing public functions

//NOTE: Testcases won't work when testing within framework. I believe this because an Application needs to have an entitlement to have Keychain access

class iOSCSRSwiftTests: XCTestCase {
    
    var publicKey: SecKey?
    var privateKey: SecKey?
    var keyBlockSize: Int?
    var publicKeyBits: NSData?
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
        
        if (publicKey != nil) && (privateKey != nil) && keyBlockSize != nil{
            //Keys only need to be created once, after they can be used over again
            return
        }
        
        let tagPublic = "com.testing.ioscsrswift.public"
        let tagPrivate = "com.testing.ioscsrswift.private"
        
        let publicKeyParameters: [String: AnyObject] = [
            String(kSecAttrIsPermanent): kCFBooleanTrue,
            String(kSecAttrApplicationTag): tagPublic as AnyObject,
            String(kSecAttrAccessible): kSecAttrAccessibleAlways
        ]
        
        let privateKeyParameters: [String: AnyObject] = [
            String(kSecAttrIsPermanent): kCFBooleanTrue,
            String(kSecAttrApplicationTag): tagPrivate as AnyObject,
            String(kSecAttrAccessible): kSecAttrAccessibleAlways
        ]
        
        //Define what type of keys to be generated here
        let parameters: [String: AnyObject] = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecAttrKeySizeInBits): 2048 as AnyObject,
            String(kSecReturnRef): kCFBooleanTrue,
            kSecPublicKeyAttrs as String: publicKeyParameters as AnyObject,
            kSecPrivateKeyAttrs as String: privateKeyParameters as AnyObject,
            ]
        
        //Use Apple Security Framework to generate keys, save them to application keychain
        let result = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)
        
        switch result {
        case errSecSuccess:
            print("Public and private key pair created")
            
            guard publicKey != nil else {
                XCTAssert(false, "Error  in setUp(). PublicKey shouldn't be nil")
                return
            }
            
            guard privateKey != nil else{
                XCTAssert(false, "Error  in setUp(). PrivateKey shouldn't be nil")
                return
            }
            
            //Set block size
            keyBlockSize = SecKeyGetBlockSize(publicKey!)
            
            //Ask keychain to provide the publicKey in bits
            let query: [String: AnyObject] = [
                String(kSecClass): kSecClassKey,
                String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
                String(kSecAttrApplicationTag): tagPublic as AnyObject,
                String(kSecReturnData): kCFBooleanTrue
            ]
            
            var tempPublicKeyBits:AnyObject?
            
            let result = SecItemCopyMatching(query as CFDictionary, &tempPublicKeyBits)
            
            switch result {
            case errSecSuccess:
                
                guard let keyBits = tempPublicKeyBits as? NSData else {
                    XCTAssert(false, "Error: couldn't cast publicKeyBits from AnyObject to Data")
                    return
                }
                
                publicKeyBits = keyBits
                
            default:
                XCTAssert(false, "Error when retrieving publicKey in bits from the keychain: \(result)")
            }
            
        default:
            XCTAssert(false, "Error occured: \(result)")
        }
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testStandardInitializer() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        
        let csr = CertificateSigningRequest()
        
        guard let csrBuild = csr.build(publicKeyBits!, privateKey: privateKey!) else{
            
            XCTAssert(false, "Could not build CSR")
            return
        }
        
        let csrString = csrBuild.base64EncodedStringWithOptions(NSDataBase64EncodingOptions.init(rawValue: 0)).stringByAddingPercentEncodingWithAllowedCharacters(NSCharacterSet.alphanumericCharacterSet())
        
        guard csrString == nil else{
            XCTAssert(false, "Could not encode CSR to string")
            return
        }
        
        if !csrString!.isEmpty{
            XCTAssert(true, csrString!)
        }else{
            
            XCTAssert(false, "Encoded CSR string was empty")
        }
        
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        /*self.measure {
            // Put the code you want to measure the time of here.
        }*/
    }
    
}
