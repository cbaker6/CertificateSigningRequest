//
//  CertificateSigningRequestConstants.swift
//  CertificateSigningRequest
//
//  Created by Corey Baker on 10/8/17.
//  Copyright © 2017 Network Reconnaissance Lab. All rights reserved.
//

import Foundation
#if canImport(Security)
import Security
#endif

// Use e.g., https://misc.daniel-marschall.de/asn.1/oid-converter/online.php to convert OID (OBJECT IDENTIFIER) to ASN.1 DER hex forms
//Guide to translate OID's to bytes for ANS.1 (Look at comment section on page): https://msdn.microsoft.com/en-us/library/bb540809(v=vs.85).aspx
/* RSA */
let OBJECT_rsaEncryptionNULL:[UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00]

// See: http://oid-info.com/get/1.2.840.113549.1.1.5
let SEQUENCE_OBJECT_sha1WithRSAEncryption:[UInt8] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 5, 0x05, 0x00]

// See: http://oid-info.com/get/1.2.840.113549.1.1.11
let SEQUENCE_OBJECT_sha256WithRSAEncryption:[UInt8] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 0x0B, 0x05, 0x00]

// See: http://oid-info.com/get/1.2.840.113549.1.1.13
let SEQUENCE_OBJECT_sha512WithRSAEncryption:[UInt8] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 0x0D, 0x05, 0x00]

/* EC */
let OBJECT_ecEncryptionNULL:[UInt8] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]

let OBJECT_ecPubicKey:[UInt8] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]

let SEQUENCE_OBJECT_sha1WithECEncryption:[UInt8] = [0x30, 0x0A, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01]

// See: http://www.oid-info.com/get/1.2.840.10045.4.3.2
let SEQUENCE_OBJECT_sha256WithECEncryption:[UInt8] = [0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]

// See: http://oid-info.com/get/1.2.840.10045.4.3.4
let SEQUENCE_OBJECT_sha512WithECEncryption:[UInt8] = [0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04]

//Enums
public enum KeyAlgorithm {
    case rsa(signatureType: signature), ec(signatureType: signature)
    
    @available(iOS 10, macCatalyst 13.0, macOS 10.12, tvOS 10.0, watchOS 3.0, *)
    public var secKeyAttrType: CFString {
        let result: CFString
        switch self {
            
        case .rsa:  result = kSecAttrKeyTypeRSA
        case .ec:   result = kSecAttrKeyTypeECSECPrimeRandom
            
        }
        return result
    }

    public var availableKeySizes: [Int] {
        let result: [Int]
        switch self {
            
        case .rsa:  result = [512, 1024, 2048]
        case .ec:   result = [256]
            
        }
        return result
    }
    
    public enum signature {
        case sha1, sha256, sha512
    }
    
    public var type:String{
        let result: String
        
        switch self {
        case .rsa(signatureType: .sha1), .rsa(signatureType: .sha256), .rsa(signatureType: .sha512):
            result = "RSA"
            
        case .ec(signatureType: .sha1), .ec(signatureType: .sha256), .ec(signatureType: .sha512):
            result = "EC"
        }
        
        return result
    }
    
    @available(iOS 10, macCatalyst 13.0, macOS 10.12, tvOS 10.0, watchOS 3.0, *)
    public var signatureAlgorithm: SecKeyAlgorithm {
        let result: SecKeyAlgorithm
        switch self {
        case .rsa(signatureType: .sha1):
            result = .rsaSignatureMessagePKCS1v15SHA1
        case .rsa(signatureType: .sha256):
            result = .rsaSignatureMessagePKCS1v15SHA256
        case .rsa(signatureType: .sha512):
            result = .rsaSignatureMessagePKCS1v15SHA512
        case .ec(signatureType: .sha1):
            result = .ecdsaSignatureMessageX962SHA1
        case .ec(signatureType: .sha256):
            result = .ecdsaSignatureMessageX962SHA256
        case .ec(signatureType: .sha512):
            result = .ecdsaSignatureMessageX962SHA512
        }
        return result
        
    }
    
    var sequenceObjectEncryptionType: [UInt8]{
        let result:[UInt8]
        switch self {
        case .rsa(signatureType: .sha1):
            result = SEQUENCE_OBJECT_sha1WithRSAEncryption
        case .rsa(signatureType: .sha256):
            result = SEQUENCE_OBJECT_sha256WithRSAEncryption
        case .rsa(signatureType: .sha512):
            result = SEQUENCE_OBJECT_sha512WithRSAEncryption
        case .ec(signatureType: .sha1):
            result = SEQUENCE_OBJECT_sha1WithECEncryption
        case .ec(signatureType: .sha256):
            result = SEQUENCE_OBJECT_sha256WithECEncryption
        case .ec(signatureType: .sha512):
            result = SEQUENCE_OBJECT_sha512WithECEncryption
        }
        
        return result
    }
    
    var objectEncryptionKeyType: [UInt8]{
        let result:[UInt8]
        switch self {
        case .rsa(signatureType: .sha1), .rsa(signatureType: .sha256), .rsa(signatureType: .sha512):
            
            result = OBJECT_rsaEncryptionNULL
            
        case .ec(signatureType: .sha1), .ec(signatureType: .sha256), .ec(signatureType: .sha512):
            result = OBJECT_ecEncryptionNULL
            
        }
        
        return result
    }
    
}

