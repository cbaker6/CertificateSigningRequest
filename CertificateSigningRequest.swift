//
//  CertificateSigningRequest.swift
//  OpportunisticRouting
//
//  Created by Corey Baker on 10/19/16.
//  Copyright © Corey Baker. All rights reserved.
//
//  This is a port of ios-csr by Ales Teska (https://github.com/ateska/ios-csr) 
//  from Objective-c to Swift 3.0. Additions have been made to allow SHA256 and SHA512.
//
//
//  MIT License
//
//  Copyright (c) 2016 Corey Baker

//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.

//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.

import Foundation
import CommonCrypto

/*
 
 Certification Request Syntax Specification: http://www.ietf.org/rfc/rfc2986.txt
 
 */

public enum SecureHashAlgorithm {
    case
    SHA1,
    SHA256,
    SHA512
}

public class CertificateSigningRequest:NSObject {
    private let countryName:String?
    private let organizationName:String?
    private let organizationUnitName:String?
    private let commonName:String?
    
    private var subjectDER:Data?
    private var secureHashAlgorithm: SecureHashAlgorithm!
    
    private let OBJECT_commonName:[UInt8] = [0x06, 0x03, 0x55, 0x04, 0x03]
    private let OBJECT_countryName:[UInt8] = [0x06, 0x03, 0x55, 0x04, 0x06]
    private let OBJECT_organizationName:[UInt8] = [0x06, 0x03, 0x55, 0x04, 0x0A]
    private let OBJECT_organizationalUnitName:[UInt8] = [0x06, 0x03, 0x55, 0x04, 0x0B]
    
    private let OBJECT_rsaEncryptionNULL:[UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00]
    
    //Guide to translate OID's to bytes for ANS.1 (Look at comment section on page): https://msdn.microsoft.com/en-us/library/bb540809(v=vs.85).aspx
    
    // See: http://oid-info.com/get/1.2.840.113549.1.1.5
    private let SEQUENCE_OBJECT_sha1WithRSAEncryption:[UInt8] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 5, 0x05, 0x00]
    
    // SeeL http://oid-info.com/get/1.2.840.113549.1.1.11
    private let SEQUENCE_OBJECT_sha256WithRSAEncryption:[UInt8] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 0x0B, 0x05, 0x00]
    
    // SeeL http://oid-info.com/get/1.2.840.113549.1.1.13
    private let SEQUENCE_OBJECT_sha512WithRSAEncryption:[UInt8] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 0x0D, 0x05, 0x00]
    
    private let SEQUENCE_tag:UInt8 = 0x30
    private let SET_tag:UInt8 = 0x31
    
    public init(commonName: String?, organizationName:String?, organizationUnitName:String?, countryName:String?, secureHashAlgorithm: SecureHashAlgorithm){
        
        self.commonName = commonName
        self.organizationName = organizationName
        self.organizationUnitName = organizationUnitName
        self.countryName = countryName
        self.subjectDER = nil
        self.secureHashAlgorithm = secureHashAlgorithm
        
        super.init()
    }
    
    public convenience override init(){
        self.init(commonName: nil, organizationName:nil, organizationUnitName:nil, countryName:nil, secureHashAlgorithm: SecureHashAlgorithm.SHA1)
    }
    
    public convenience init(cSecureHashAlgorithm: SecureHashAlgorithm){
        self.init(commonName: nil, organizationName:nil, organizationUnitName:nil, countryName:nil, secureHashAlgorithm: cSecureHashAlgorithm)
    }
    
    public func build(_ publicKeyBits:Data, privateKey: SecKey) -> Data?{
        
        var certificationRequestInfo = buldCertificationRequestInfo(publicKeyBits)
        var shaBytes:[UInt8]
        var padding:SecPadding
        var certificationRequestInfoBytes = [UInt8](repeating: 0, count: certificationRequestInfo.count)
        certificationRequestInfo.copyBytes(to: &certificationRequestInfoBytes, count: certificationRequestInfo.count)
        var digest:[UInt8]
        
        switch secureHashAlgorithm! {
        case .SHA1:
            
            // Build signature - step 1: SHA1 hash
            var SHA1 = CC_SHA1_CTX()
            CC_SHA1_Init(&SHA1)
            CC_SHA1_Update(&SHA1, certificationRequestInfoBytes, CC_LONG(certificationRequestInfo.count))
            digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
            CC_SHA1_Final(&digest, &SHA1)
            shaBytes = SEQUENCE_OBJECT_sha1WithRSAEncryption
            padding = SecPadding.PKCS1SHA1
            
        case .SHA256:
            
            // Build signature - step 1: SHA256 hash
            var SHA256 = CC_SHA256_CTX()
            CC_SHA256_Init(&SHA256)
            CC_SHA256_Update(&SHA256, certificationRequestInfoBytes, CC_LONG(certificationRequestInfo.count))
            digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            CC_SHA256_Final(&digest, &SHA256)
            shaBytes = SEQUENCE_OBJECT_sha256WithRSAEncryption
            padding = SecPadding.PKCS1SHA256
            
        case .SHA512:
            
            // Build signature - step 1: SHA512 hash
            var SHA512 = CC_SHA512_CTX()
            CC_SHA512_Init(&SHA512)
            CC_SHA512_Update(&SHA512, certificationRequestInfoBytes, CC_LONG(certificationRequestInfo.count))
            digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
            CC_SHA512_Final(&digest, &SHA512)
            shaBytes = SEQUENCE_OBJECT_sha512WithRSAEncryption
            padding = SecPadding.PKCS1SHA512
        }
        
        
        // Build signature - step 2: Sign hash
        var signature = [UInt8](repeating: 0, count: 256)
        var signatureLen = signature.count
        
        let result = SecKeyRawSign(privateKey, padding, digest, digest.count, &signature, &signatureLen)
        
        if result != errSecSuccess{
            print("Error: \(result)")
            return nil
        }
        
        var certificationRequest = Data(capacity: 1024)
        certificationRequest.append(certificationRequestInfo)
        certificationRequest.append(shaBytes, count: shaBytes.count)
        
        var signData = Data(capacity: 257)
        let zero:UInt8 = 0 // Prepend zero
        signData.append(zero)
        signData.append(signature, count: signatureLen)
        appendBITSTRING(signData, into: &certificationRequest)
        
        enclose(&certificationRequest, by: SEQUENCE_tag) // Enclose into SEQUENCE
        
        return certificationRequest
    }
    
    func buldCertificationRequestInfo(_ publicKeyBits:Data) -> Data{
        var certificationRequestInfo = Data(capacity: 256)
        
        //Add version
        let version: [UInt8] = [0x02, 0x01, 0x00] // ASN.1 Representation of integer with value 1
        certificationRequestInfo.append(version, count: version.count)
        
        //Add subject
        var subject = Data(capacity: 256)
        if countryName != nil{
            appendSubjectItem(OBJECT_countryName, value: countryName!, into: &subject)
        }
        
        if organizationName != nil{
            appendSubjectItem(OBJECT_organizationName, value: organizationName!, into: &subject)
        }
        
        if organizationUnitName != nil {
            appendSubjectItem(OBJECT_organizationalUnitName, value: organizationUnitName!, into: &subject)
        }
        
        if commonName != nil{
            appendSubjectItem(OBJECT_commonName, value: commonName!, into: &subject)
        }
        
        enclose(&subject, by: SEQUENCE_tag)// Enclose into SEQUENCE
        
        subjectDER = subject
        
        certificationRequestInfo.append(subject)
        
        //Add public key info
        let publicKeyInfo = buildPublicKeyInfo(publicKeyBits)
        certificationRequestInfo.append(publicKeyInfo)
        
        // Add attributes
        let attributes:[UInt8] = [0xA0, 0x00]
        certificationRequestInfo.append(attributes, count: attributes.count)
        
        enclose(&certificationRequestInfo, by: SEQUENCE_tag) // Enclose into SEQUENCE
        
        return certificationRequestInfo
    }
    
    /// Utility class methods ...
    func buildPublicKeyInfo(_ publicKeyBits:Data)-> Data{
        
        var publicKeyInfo = Data(capacity: 390)
        
        publicKeyInfo.append(OBJECT_rsaEncryptionNULL, count: OBJECT_rsaEncryptionNULL.count)
        enclose(&publicKeyInfo, by: SEQUENCE_tag) // Enclose into SEQUENCE
        
        var publicKeyASN = Data(capacity: 260)
        
        let mod = getPublicKeyMod(publicKeyBits)
        let integer:UInt8 = 0x02 //Integer
        publicKeyASN.append(integer)
        appendDERLength(mod.count, into: &publicKeyASN)
        publicKeyASN.append(mod)
        
        let exp = getPublicKeyExp(publicKeyBits)
        publicKeyASN.append(integer)
        appendDERLength(exp.count, into: &publicKeyASN)
        publicKeyASN.append(exp)
        
        enclose(&publicKeyASN, by: SEQUENCE_tag)// Enclose into ??
        prependByte(0x00, into: &publicKeyASN) //Prepend 0 (?)
        
        appendBITSTRING(publicKeyASN, into: &publicKeyInfo)
        
        enclose(&publicKeyInfo, by: SEQUENCE_tag) // Enclose into SEQUENCE
        
        return publicKeyInfo
    }
    
    func appendSubjectItem(_ what:[UInt8], value: String, into: inout Data ) ->(){
        
        if what.count != 5{
            print("Error: attempting to a non-subject item")
            return
        }
        
        var subjectItem = Data(capacity: 128)
        
        subjectItem.append(what, count: what.count)
        appendUTF8String(string: value, into: &subjectItem)
        enclose(&subjectItem, by: SEQUENCE_tag)
        enclose(&subjectItem, by: SET_tag)
        
        into.append(subjectItem)
    }
    
    func appendUTF8String(string: String, into: inout Data) ->(){
        
        let strType:UInt8 = 0x0C //UTF8STRING
    
        into.append(strType)
        appendDERLength(string.lengthOfBytes(using: String.Encoding.utf8), into: &into)
        into.append(string.data(using: String.Encoding.utf8)!)
    }
    
    func appendDERLength(_ length: Int, into: inout Data){
        
        assert(length < 0x8000)
        
        if length < 128{
            let d = UInt8(length)
            into.append(d)
            
        }else if (length < 0x100){
            
            var d: [UInt8] = [0x81, UInt8(length & 0xFF)]
            into.append(&d, count: d.count)
            
        }else if length < 0x8000{
            
            let preRes:UInt = UInt(length & 0xFF00)
            let res = UInt8(preRes >> 8)
            var d: [UInt8] = [0x82, res, UInt8(length & 0xFF)]
            into.append(&d, count: d.count)
        }
    }
    
    func appendBITSTRING(_ data: Data, into: inout Data)->(){
        
        let strType:UInt8 = 0x03 //BIT STRING
        into.append(strType)
        appendDERLength(data.count, into: &into)
        into.append(data)
    }
    
    func enclose(_ data: inout Data, by: UInt8){
        
        var newData = Data(capacity: data.count + 4)
        
        newData.append(by)
        appendDERLength(data.count, into: &newData)
        newData.append(data)
        
        data = newData
    }
    
    func prependByte(_ byte: UInt8, into: inout Data)->(){
     
        var newData = Data(capacity: into.count + 1)
        
        newData.append(byte)
        newData.append(into)
        
        into = newData
    }
    
    // From http://stackoverflow.com/questions/3840005/how-to-find-out-the-modulus-and-exponent-of-rsa-public-key-on-iphone-objective-c
    
    func getPublicKeyExp(_ publicKeyBits:Data)->Data{
        
        var iterator = 0
        
        iterator+=1 // TYPE - bit stream - mod + exp
        _ = derEncodingGetSizeFrom(publicKeyBits, at: &iterator) // Total size
        
        iterator+=1 // TYPE - bit stream mod
        let modSize = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)
        iterator += modSize
        
        iterator+=1 // TYPE - bit stream exp
        let expSize = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)
        
        let range:Range<Int> = iterator ..< (iterator + expSize)
        
        return publicKeyBits.subdata(in: range)
    }
    
    func getPublicKeyMod(_ publicKeyBits: Data)->Data{
        
        var iterator = 0
        
        iterator+=1 // TYPE - bit stream - mod + exp
        _ = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)
        
        iterator+=1 // TYPE - bit stream mod
        let modSize = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)
        
        let range:Range<Int> = iterator ..< (iterator + modSize)
        
        return publicKeyBits.subdata(in: range)
    }
    
    func derEncodingGetSizeFrom(_ buf: Data, at iterator: inout Int)->Int{
        
        var data = [UInt8](repeating: 0, count: buf.count)
        buf.copyBytes(to: &data, count: buf.count)
        
        var itr = iterator
        var numOfBytes = 1
        var ret = 0
        
        if data[itr] > 0x80{
            numOfBytes = Int((data[itr] - 0x80))
            itr += 1
        }

        for index in 0 ..< numOfBytes {
            ret = (ret * 0x100) + Int(data[itr + index])
        }
        
        iterator = itr + numOfBytes
        
        return ret
    }
}
