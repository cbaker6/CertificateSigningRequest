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

// Use e.g., https://misc.daniel-marschall.de/asn.1/oid-converter/online.php
// to convert OID (OBJECT IDENTIFIER) to ASN.1 DER hex forms
// Guide to translate OID's to bytes for ANS.1 (Look at comment section on page):
// https://msdn.microsoft.com/en-us/library/bb540809(v=vs.85).aspx
/* RSA */
let objectRSAEncryptionNULL: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00]

// See: http://oid-info.com/get/1.2.840.113549.1.1.5
let sequenceObjectSHA1WithRSAEncryption: [UInt8] =
    [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 5, 0x05, 0x00]

// See: http://oid-info.com/get/1.2.840.113549.1.1.11
let sequenceObjectSHA256WithRSAEncryption: [UInt8] =
    [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 0x0B, 0x05, 0x00]

// See: http://oid-info.com/get/1.2.840.113549.1.1.13
let sequenceObjectSHA512WithRSAEncryption: [UInt8] =
    [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 0x0D, 0x05, 0x00]

/* EC */
let objectECEncryptionNULL: [UInt8] =
    [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]

let objectECPubicKey: [UInt8] =
    [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]

let sequenceObjectSHA1WithECEncryption: [UInt8] =
    [0x30, 0x0A, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01]

// See: http://www.oid-info.com/get/1.2.840.10045.4.3.2
let sequenceObjectSHA256WithECEncryption: [UInt8] =
    [0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]

// See: http://oid-info.com/get/1.2.840.10045.4.3.4
let sequenceObjectSHA512WithECEncryption: [UInt8] =
    [0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04]

//Enums
public enum KeyAlgorithm {
    // swiftlint:disable:next identifier_name
    case rsa(signatureType: Signature), ec(signatureType: Signature)

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

    public enum Signature {
        case sha1, sha256, sha512
    }

    public var type: String {
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

    var sequenceObjectEncryptionType: [UInt8] {
        let result: [UInt8]
        switch self {
        case .rsa(signatureType: .sha1):
            result = sequenceObjectSHA1WithRSAEncryption
        case .rsa(signatureType: .sha256):
            result = sequenceObjectSHA256WithRSAEncryption
        case .rsa(signatureType: .sha512):
            result = sequenceObjectSHA512WithRSAEncryption
        case .ec(signatureType: .sha1):
            result = sequenceObjectSHA1WithECEncryption
        case .ec(signatureType: .sha256):
            result = sequenceObjectSHA256WithECEncryption
        case .ec(signatureType: .sha512):
            result = sequenceObjectSHA512WithECEncryption
        }

        return result
    }

    var objectEncryptionKeyType: [UInt8] {
        let result: [UInt8]
        switch self {
        case .rsa(signatureType: .sha1), .rsa(signatureType: .sha256), .rsa(signatureType: .sha512):

            result = objectRSAEncryptionNULL

        case .ec(signatureType: .sha1), .ec(signatureType: .sha256), .ec(signatureType: .sha512):
            result = objectECEncryptionNULL

        }

        return result
    }
}
