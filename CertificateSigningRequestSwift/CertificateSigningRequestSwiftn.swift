//
//  CertificateSigningRequestSwiftn.swift
//  CertificateSigningRequestSwift
//
//  Created by Corey Baker on 10/8/17.
//  Copyright © Corey Baker. All rights reserved.
//

import Foundation

/*
 //DER Tags in byte form: http://luca.ntop.org/Teaching/Appunti/asn1.html
 let kCSRTagInteger = 0x02
 let kCSRBitString = 0x03
 let kCSROctetString = 0x04
 let kCSRNull = 0x05
 let kCSRObjectIdentifier = 0x06
 let kCSRSequence = 0x10
 
 // RSA
 let kCSRRSAEncryption:[UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05]
 
 // OID Description: http://oid-info.com/get/1.2.840.113549.1.1.5
 let kCSRSHA1RSAEncryption:[UInt8] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 5, 0x05]
 
 // OID Description: http://oid-info.com/get/1.2.840.113549.1.1.11
 let kCSRSHA256RSAEncryption:[UInt8] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 0x0B, 0x05]
 
 // OID Description: http://oid-info.com/get/1.2.840.113549.1.1.13
 let kCSRSHA512RSAEncryption:[UInt8] = [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 0x0D, 0x05]
 
 // EC
 let kCSRECEncryption:[UInt8] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
 
 let kCSRECPubicKey:[UInt8] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
 
 let kCSRSHA1ECEncryption:[UInt8] = [0x30, 0x0A, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01]
 
 // OID Description: http://www.oid-info.com/get/1.2.840.10045.4.3.2
 let kCSRSHA256ECEncryption:[UInt8] = [0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]
 
 // OID Description: http://oid-info.com/get/1.2.840.10045.4.3.4
 let kCSRSHA512ECEncryption:[UInt8] = [0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04]
 */


public class CertificateSigningRequestN:NSObject {
    
    private let countryName:String?
    private let organizationName:String?
    private let organizationUnitName:String?
    private let commonName:String?
    private var keyAlgorithm: KeyAlgorithm!
    private var subjectDER:Data?
    
    public init(commonName: String?, organizationName:String?, organizationUnitName:String?, countryName:String?, keyAlgorithm: KeyAlgorithm){
        
        self.commonName = commonName
        self.organizationName = organizationName
        self.organizationUnitName = organizationUnitName
        self.countryName = countryName
        self.subjectDER = nil
        self.keyAlgorithm = keyAlgorithm
        
        super.init()
    }
    
    public convenience override init(){
        self.init(commonName: nil, organizationName:nil, organizationUnitName:nil, countryName:nil, keyAlgorithm: KeyAlgorithm.rsa(signatureType: .sha512))
    }
    
    public convenience init(keyAlgorithm: KeyAlgorithm){
        self.init(commonName: nil, organizationName:nil, organizationUnitName:nil, countryName:nil, keyAlgorithm: keyAlgorithm)
    }
    
    public func buildAndEncodeDataAsString(_ publicKey:Data, privateKey: SecKey)-> String? {
        /*
        guard let buildData = self.build(publicKey, privateKey: privateKey) else{
            return nil
        }
        
        return buildData.base64EncodedString(options: NSData.Base64EncodingOptions(rawValue: 0)).addingPercentEncoding(withAllowedCharacters: CharacterSet.urlQueryAllowed)
        */
        return nil //delete after uncommenting above
    }
    
    public func buildCSRAndReturnString(_ publicKey:Data, privateKey: SecKey)-> String? {
        
        guard let csrString = self.buildAndEncodeDataAsString(publicKey, privateKey: privateKey) else{
            return nil
        }
        
        let head = "-----BEGIN CERTIFICATE REQUEST-----\n";
        let foot = "-----END CERTIFICATE REQUEST-----\n";
        var isMultiple = false;
        var newCSRString = head;
        
        //Check if string size is a multiple of 64
        if (csrString.count % 64 == 0){
            isMultiple = true;
        }
        
        for (i, char) in csrString.enumerated() {
            newCSRString.append(char)
            
            if ((i != 0) && ((i+1) % 64 == 0)){
                newCSRString.append("\n")
            }
            
            if ((i == csrString.count-1) && !isMultiple){
                newCSRString.append("\n")
            }
            
        }
        
        newCSRString = newCSRString+foot
        
        return newCSRString
    }
    
    func getPublicKey(_ publicKey:Data)->Data{
        
        //Current only supports uncompressed keys, 65=1+32+32
        var iterator = 0
        
        _ = derEncodingSpecificSize(publicKey, at: &iterator, numberOfBytes: 8)
        
        let range:Range<Int> = 0 ..< publicKey.count
        
        return publicKey.subdata(in: range)
    }
    
    func derEncodingSpecificSize(_ dataBuffer: Data, at iterator: inout Int, numberOfBytes: Int)->Int{
        
        var data = [UInt8](repeating: 0, count: dataBuffer.count)
        dataBuffer.copyBytes(to: &data, count: dataBuffer.count)
        
        if data[0] != 0x04{
            print("Error, framework only supports uncompressed keys")
        }
        
        return dataBuffer.count
    }
    
    // Code snippits from: http://stackoverflow.com/questions/3840005/how-to-find-out-the-modulus-and-exponent-of-rsa-public-key-on-iphone-objective-c
    func getPublicKeyExp(_ publicKey:Data)->Data{
        
        var iterator = 0
        if publicKey.count == 0{
            return publicKey
        }
        
        iterator+=1 // TYPE - bit stream - mod + exp
        _ = derEncodingGetSizeFrom(publicKey, at: &iterator) // Total size
        
        iterator+=1 // TYPE - bit stream mod
        let modulusSize  = derEncodingGetSizeFrom(publicKey, at: &iterator)
        iterator += modulusSize
        
        iterator+=1 // TYPE - bit stream exp
        let expSize = derEncodingGetSizeFrom(publicKey, at: &iterator)
        
        let range:Range<Int> = iterator ..< (iterator + expSize)
        
        return publicKey.subdata(in: range)
    }
    
    func getPublicKeyMod(_ publicKey: Data)->Data{
        
        var iterator = 0
        
        if publicKey.count == 0{
            return publicKey
        }
        
        iterator+=1 // TYPE - bit stream - mod + exp
        _ = derEncodingGetSizeFrom(publicKey, at: &iterator) // Total size
        
        iterator+=1 // TYPE - bit stream mod
        let modulusSize  = derEncodingGetSizeFrom(publicKey, at: &iterator)
        
        let range:Range<Int> = iterator ..< (iterator + modulusSize )
        
        return publicKey.subdata(in: range)
    }
    

    func derEncodingGetSizeFrom(_ dataBuffer: Data, at iterator: inout Int)->Int{
        
        var data = [UInt8](repeating: 0, count: dataBuffer.count)
        dataBuffer.copyBytes(to: &data, count: dataBuffer.count)
        
        var i = iterator
        var numberOfBytes = 1
        var returnEncoded = 0
        
        if data[i] > 0x80{
            numberOfBytes = Int((data[i] - 0x80))
            i += 1
        }
        
        for index in 0 ..< numberOfBytes {
            returnEncoded = (returnEncoded * 0x100) + Int(data[i + index])
        }
        
        iterator = i + numberOfBytes
        
        return returnEncoded
    }

}
