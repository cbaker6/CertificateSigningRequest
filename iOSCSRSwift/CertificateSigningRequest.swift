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

/*
 
 Certification Request Syntax Specification: http://www.ietf.org/rfc/rfc2986.txt
 
 */


//See: http://stackoverflow.com/questions/24099520/commonhmac-in-swift
public enum CryptoAlgorithm {
    case md5, sha1, sha224, sha256, sha384, sha512
    
    var HMACAlgorithm: CCHmacAlgorithm {
        var result: Int = 0
        switch self {
        case .md5:      result = kCCHmacAlgMD5
        case .sha1:     result = kCCHmacAlgSHA1
        case .sha224:   result = kCCHmacAlgSHA224
        case .sha256:   result = kCCHmacAlgSHA256
        case .sha384:   result = kCCHmacAlgSHA384
        case .sha512:   result = kCCHmacAlgSHA512
        }
        return CCHmacAlgorithm(result)
    }
    
    var digestLength: Int {
        var result: Int32 = 0
        switch self {
        case .md5:      result = CC_MD5_DIGEST_LENGTH
        case .sha1:     result = CC_SHA1_DIGEST_LENGTH
        case .sha224:   result = CC_SHA224_DIGEST_LENGTH
        case .sha256:   result = CC_SHA256_DIGEST_LENGTH
        case .sha384:   result = CC_SHA384_DIGEST_LENGTH
        case .sha512:   result = CC_SHA512_DIGEST_LENGTH
        }
        return Int(result)
    }
}

public class CertificateSigningRequest:NSObject {
    private let countryName:String?
    private let organizationName:String?
    private let organizationUnitName:String?
    private let commonName:String?
    
    private var subjectDER:NSData?
    private var cryptoAlgorithm: CryptoAlgorithm!
    
    private let OBJECT_commonName:[UInt8] = [0x06, 0x03, 0x55, 0x04, 0x03]
    private let OBJECT_countryName:[UInt8] = [0x06, 0x03, 0x55, 0x04, 0x06]
    private let OBJECT_organizationName:[UInt8] = [0x06, 0x03, 0x55, 0x04, 0x0A]
    private let OBJECT_organizationalUnitName:[UInt8] = [0x06, 0x03, 0x55, 0x04, 0x0B]
    
    private let OBJECT_rsaEncryptionNULL:[UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00]
    
    //Guide to translate OID's to bytes for ANS.1 (Look at comment section on page): https://msdn.microsoft.com/en-us/library/bb540809(v=vs.85).aspx
    
    // See: http://oid-info.com/get/1.2.840.113549.1.1.5
    private let SEQUENCE_OBJECT_sha1WithRSAEncryption:[UInt8] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 5, 0x05, 0x00]
    
    // See: http://oid-info.com/get/1.2.840.113549.1.1.11
    private let SEQUENCE_OBJECT_sha256WithRSAEncryption:[UInt8] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 0x0B, 0x05, 0x00]
    
    // See: http://oid-info.com/get/1.2.840.113549.1.1.13
    private let SEQUENCE_OBJECT_sha512WithRSAEncryption:[UInt8] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 0x0D, 0x05, 0x00]
    
    private let SEQUENCE_tag:UInt8 = 0x30
    private let SET_tag:UInt8 = 0x31
    
    public init(commonName: String?, organizationName:String?, organizationUnitName:String?, countryName:String?, cryptoAlgorithm: CryptoAlgorithm){
        
        self.commonName = commonName
        self.organizationName = organizationName
        self.organizationUnitName = organizationUnitName
        self.countryName = countryName
        self.subjectDER = nil
        self.cryptoAlgorithm = cryptoAlgorithm
        
        super.init()
    }
    
    public convenience override init(){
        self.init(commonName: nil, organizationName:nil, organizationUnitName:nil, countryName:nil, cryptoAlgorithm: CryptoAlgorithm.sha1)
    }
    
    public convenience init(cryptoAlgorithm: CryptoAlgorithm){
        self.init(commonName: nil, organizationName:nil, organizationUnitName:nil, countryName:nil, cryptoAlgorithm: cryptoAlgorithm)
    }
    
    public func build(publicKeyBits:NSData, privateKey: SecKey) -> NSData?{
        
        var certificationRequestInfo = buldCertificationRequestInfo(publicKeyBits)
        var shaBytes:[UInt8]
        var padding:SecPadding
       
        var certificationRequestInfoBytes = [UInt8](count: certificationRequestInfo.length, repeatedValue: 0)
        certificationRequestInfo.getBytes(&certificationRequestInfoBytes, length: certificationRequestInfo.length)
    
        var digest:[UInt8]
        
        switch cryptoAlgorithm! {
        case .sha1:
            
            // Build signature - step 1: SHA1 hash
            var SHA1 = CC_SHA1_CTX()
            CC_SHA1_Init(&SHA1)
            CC_SHA1_Update(&SHA1, certificationRequestInfoBytes, CC_LONG(certificationRequestInfo.length))
            digest = [UInt8](count: cryptoAlgorithm.digestLength, repeatedValue: 0)
            CC_SHA1_Final(&digest, &SHA1)
            shaBytes = SEQUENCE_OBJECT_sha1WithRSAEncryption
            padding = SecPadding.PKCS1SHA1
            
        case .sha256:
            
            // Build signature - step 1: SHA256 hash
            var SHA256 = CC_SHA256_CTX()
            CC_SHA256_Init(&SHA256)
            CC_SHA256_Update(&SHA256, certificationRequestInfoBytes, CC_LONG(certificationRequestInfo.length))
            digest = [UInt8](count: cryptoAlgorithm.digestLength, repeatedValue: 0)
            CC_SHA256_Final(&digest, &SHA256)
            shaBytes = SEQUENCE_OBJECT_sha256WithRSAEncryption
            padding = SecPadding.PKCS1SHA256
            
        case .sha512:
            
            // Build signature - step 1: SHA512 hash
            var SHA512 = CC_SHA512_CTX()
            CC_SHA512_Init(&SHA512)
            CC_SHA512_Update(&SHA512, certificationRequestInfoBytes, CC_LONG(certificationRequestInfo.length))
            digest = [UInt8](count: cryptoAlgorithm.digestLength, repeatedValue: 0)
            CC_SHA512_Final(&digest, &SHA512)
            shaBytes = SEQUENCE_OBJECT_sha512WithRSAEncryption
            padding = SecPadding.PKCS1SHA512
            
        default:
            
            print("Error: crypto algotirthm \(cryptoAlgorithm) is not implemented")
            return nil
        }
        
        
        // Build signature - step 2: Sign hash
        var signature = [UInt8](count: 256, repeatedValue: 0)
        var signatureLen = signature.count
        
        let result = SecKeyRawSign(privateKey, padding, digest, digest.count, &signature, &signatureLen)
        
        if result != errSecSuccess{
            print("Error: \(result)")
            return nil
        }
        
        var certificationRequest = NSMutableData()
        certificationRequest = NSMutableData(bytes: &certificationRequest, length: 1024)
        certificationRequest.appendBytes(&certificationRequestInfo, length: 1)
        certificationRequest.appendBytes(&shaBytes, length: shaBytes.count)
        
        var signData = NSMutableData()
        signData = NSMutableData(bytes: &signData, length: 257)
        var zero:UInt8 = 0 // Prepend zero
        signData.appendBytes(&zero, length: 1)
        signData.appendBytes(&signature, length: signatureLen)
        appendBITSTRING(signData, into: &certificationRequest)
        
        enclose(&certificationRequest, by: SEQUENCE_tag) // Enclose into SEQUENCE
        
        return certificationRequest
    }
    
    func buldCertificationRequestInfo(publicKeyBits:NSData) -> NSData{
        var certificationRequestInfo = NSMutableData()
        certificationRequestInfo = NSMutableData(bytes: &certificationRequestInfo, length: 256)
        
        //Add version
        let version: [UInt8] = [0x02, 0x01, 0x00] // ASN.1 Representation of integer with value 1
        certificationRequestInfo.appendBytes(version, length: version.count)
        
        //Add subject
        var subject = NSMutableData()
        subject = NSMutableData(bytes: &subject, length: 256)
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
        
        certificationRequestInfo.appendBytes(&subject, length: 1)
        
        //Add public key info
        var publicKeyInfo = buildPublicKeyInfo(publicKeyBits)
        certificationRequestInfo.appendBytes(&publicKeyInfo, length: 1)
        
        // Add attributes
        let attributes:[UInt8] = [0xA0, 0x00]
        certificationRequestInfo.appendBytes(attributes, length: attributes.count)
        
        enclose(&certificationRequestInfo, by: SEQUENCE_tag) // Enclose into SEQUENCE
        
        return certificationRequestInfo
    }
    
    /// Utility class methods ...
    func buildPublicKeyInfo(publicKeyBits:NSData)-> NSData{
        
        var publicKeyInfo = NSMutableData()
        publicKeyInfo = NSMutableData(bytes: &publicKeyInfo, length: 390)
        publicKeyInfo.appendBytes(OBJECT_rsaEncryptionNULL, length: OBJECT_rsaEncryptionNULL.count)
        enclose(&publicKeyInfo, by: SEQUENCE_tag) // Enclose into SEQUENCE
        
        var publicKeyASN = NSMutableData()
        publicKeyASN = NSMutableData(bytes: &publicKeyASN, length: 260)
        
        var mod = getPublicKeyMod(publicKeyBits)
        var integer:UInt8 = 0x02 //Integer
        publicKeyASN.appendBytes(&integer, length: 1)
        appendDERLength(mod.length, into: &publicKeyASN)
        publicKeyASN.appendBytes(&mod, length: 1)
        
        var exp = getPublicKeyExp(publicKeyBits)
        publicKeyASN.appendBytes(&integer, length: 1)
        appendDERLength(exp.length, into: &publicKeyASN)
        publicKeyASN.appendBytes(&exp, length: 1)
        
        enclose(&publicKeyASN, by: SEQUENCE_tag)// Enclose into ??
        prependByte(0x00, into: &publicKeyASN) //Prepend 0 (?)
        
        appendBITSTRING(publicKeyASN, into: &publicKeyInfo)
        
        enclose(&publicKeyInfo, by: SEQUENCE_tag) // Enclose into SEQUENCE
        
        return publicKeyInfo
    }
    
    func appendSubjectItem(what:[UInt8], value: String, inout into: NSMutableData) ->(){
        
        if what.count != 5{
            print("Error: attempting to a non-subject item")
            return
        }
        
        var subjectItem = NSMutableData()
        subjectItem = NSMutableData(bytes: &subjectItem, length:  128)
        subjectItem.appendBytes(what, length: what.count)
        appendUTF8String(value, into: &subjectItem)
        enclose(&subjectItem, by: SEQUENCE_tag)
        enclose(&subjectItem, by: SET_tag)
        
        into.appendBytes(&subjectItem, length: 1)
    }
    
    func appendUTF8String(string: String, inout into: NSMutableData) ->(){
        
        var strType:UInt8 = 0x0C //UTF8STRING
    
        into.appendBytes(&strType, length: 1)
        appendDERLength(string.lengthOfBytesUsingEncoding(NSUTF8StringEncoding), into: &into)
        var mutableStringData = string.dataUsingEncoding(NSUTF8StringEncoding)!
        into.appendBytes(&mutableStringData, length: 1)
    }
    
    func appendDERLength(length: Int, inout into: NSMutableData){
        
        assert(length < 0x8000)
        
        if length < 128{
            var d = UInt8(length)
            into.appendBytes(&d, length: 1)
            
        }else if (length < 0x100){
            
            var d: [UInt8] = [0x81, UInt8(length & 0xFF)]
            into.appendBytes(&d, length: d.count)
            
        }else if length < 0x8000{
            
            let preRes:UInt = UInt(length & 0xFF00)
            let res = UInt8(preRes >> 8)
            var d: [UInt8] = [0x82, res, UInt8(length & 0xFF)]
            into.appendBytes(&d, length: d.count)
        }
    }
    
    func appendBITSTRING(data: NSData, inout into: NSMutableData)->(){
        
        var strType:UInt8 = 0x03 //BIT STRING
        into.appendBytes(&strType, length: 1)
        var mutableData = data
        appendDERLength(mutableData.length, into: &into)
        into.appendBytes(&mutableData, length: 1)
    }
    
    func enclose(inout data: NSMutableData, by: UInt8){
        
        var newData = NSMutableData()
        newData = NSMutableData(bytes: &newData, length: data.length + 4)
        var mutableBy = by
        newData.appendBytes(&mutableBy, length: 1)
        appendDERLength(data.length, into: &newData)
        newData.appendBytes(&data, length: 1)
        
        data = newData
    }
    
    func prependByte(byte: UInt8, inout into: NSMutableData)->(){
     
        var newData = NSMutableData()
        newData = NSMutableData(bytes: &newData, length: into.length + 1)
        var mutableByte = byte
        newData.appendBytes(&mutableByte, length: 1)
        newData.appendBytes(&into, length: 1)
        
        into = newData
    }
    
    // From http://stackoverflow.com/questions/3840005/how-to-find-out-the-modulus-and-exponent-of-rsa-public-key-on-iphone-objective-c
    
    func getPublicKeyExp(publicKeyBits:NSData)->NSData{
        
        var iterator = 0
        
        iterator+=1 // TYPE - bit stream - mod + exp
        _ = derEncodingGetSizeFrom(publicKeyBits, at: &iterator) // Total size
        
        iterator+=1 // TYPE - bit stream mod
        let modSize = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)
        iterator += modSize
        
        iterator+=1 // TYPE - bit stream exp
        let expSize = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)
        
        return publicKeyBits.subdataWithRange(NSMakeRange(iterator, expSize))
    }
    
    func getPublicKeyMod(publicKeyBits: NSData)->NSData{
        
        var iterator = 0
        
        iterator+=1 // TYPE - bit stream - mod + exp
        _ = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)
        
        iterator+=1 // TYPE - bit stream mod
        let modSize = derEncodingGetSizeFrom(publicKeyBits, at: &iterator)
        
        return publicKeyBits.subdataWithRange(NSMakeRange(iterator, modSize))
    }
    
    func derEncodingGetSizeFrom(buf: NSData, inout at iterator: Int)->Int{
        
        var data = [UInt8](count: buf.length, repeatedValue: 0)
        buf.getBytes(&data, length: buf.length)
        
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
