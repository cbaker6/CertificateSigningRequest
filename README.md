# CertificateSigningRequest
![Swift Version 5.0](https://img.shields.io/badge/Swift-v5.0-yellow.svg)
[![CI Status](https://img.shields.io/travis/cbaker6/CertificateSigningRequest.svg?style=flat)](https://travis-ci.org/cbaker6/CertificateSigningRequest)
[![SPM](https://img.shields.io/badge/Swift%20Package%20Manager-compatible-brightgreen.svg)](https://github.com/apple/swift-package-manager)
[![Version](https://img.shields.io/cocoapods/v/CertificateSigningRequest.svg?style=flat)](https://cocoapods.org/pods/CertificateSigningRequest)
[![License](https://img.shields.io/cocoapods/l/CertificateSigningRequest.svg?style=flat)](https://cocoapods.org/pods/CertificateSigningRequest)
[![Platform](https://img.shields.io/cocoapods/p/CertificateSigningRequest.svg?style=flat)](https://cocoapods.org/pods/CertificateSigningRequest)

Generate a certificate signing request (CSR) in iOS/macOS using Swift.

Supports RSA (key size: 512, 1024, 2048) and EC inside/outside of secure enclave (iOS only supports 256 bit keys for now), SHA1, SHA256, and SHA512. 

To use, follow the following steps:

1. Generate your publicKey/privateKey pair. This can be done using Keychain in iOS. An example can be found in the `generateKeysAndStoreInKeychain` function in the [testfile](https://github.com/cbaker6/CertificateSigningRequest/blob/master/Example/Tests/Tests.swift#L440).
2.  Get your publicKey in bits by querying it from the iOS keychain using `String(kSecReturnData): kCFBooleanTrue` in your query. For example:

```swift
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
guard let publicKeyBits = tempPublicKeyBits as? Data else {
    return
}
```
3. Initiatlize the `CertificateSigningRequest` using `KeyAlgorithm.ec` or `KeyAlgorithm.rsa` (an example of how to do can be found in the [test](https://github.com/cbaker6/CertificateSigningRequest/blob/master/Example/Tests/Tests.swift#L34) file: 
```swift 
let algorithm = KeyAlgorithm.ec(signatureType: .sha256)
let csr = CertificateSigningRequest()
let csr = CertificateSigningRequest(keyAlgorithm: algorithm)
let csr = CertificateSigningRequest(commonName: String?, organizationName:String?, organizationUnitName:String?, countryName:String?, stateOrProvinceName:String?, localityName:String?, keyAlgorithm: algorithm)
```

4. Then simply build your CSR using your publicKey(bits) and privateKey using:
 ```swift 
 let builtCSR = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey)
 //Or if you want `CertificateSigningRequest` to verify the signature after building, pass in your publicKey to the same method:
 let builtCSR = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey, publicKey: publicKey)
 ``` 
- Two other methods are available depending on your needs.
- To get CSR without header and footer info use: `let builtCSR = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey)`.
- To get CSR as Data use: `let builtCSR = csr.build(publicKeyBits, privateKey: privateKey)`.

Note:

You can test if your CSRs are correct by running and setting a break point the [test file](https://github.com/cbaker6/CertificateSigningRequest/blob/master/Example/Tests/Tests.swift#L66). You can also let all test run and test the different CSR's. The output of the CSR will print in the console window. You can output the CSR's and your own app by printing to the console and check if they are created correctly by pasting them here: https://redkestrel.co.uk/products/decoder/ or by using openssl.

## Example

To run the example project, clone the repo, and run `pod install` from the Example directory first. An example certificate from this framework is below:

```
-----BEGIN CERTIFICATE REQUEST-----
MIIBMDCB1wIBADB1MQswCQYDVQQGDAJVUzELMAkGA1UECAwCS1kxDTALBgNVBAcM
BFRlc3QxDTALBgNVBAoMBFRlc3QxDTALBgNVBAsMBFRlc3QxLDAqBgNVBAMMI0Nl
cnRpZmljYXRlU2lnbmluZ1JlcXVlc3RTd2lmdCBUZXN0MFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAExrSyR8PBMPaW9llanSqOhl3l5LhlXv0LwYEW+Yhg8e5MOPs4
SlG8f33OFVUPPNWd09TnmtKg+P4VTuEfJphsqKAAMAoGCCqGSM49BAMCA0gAMEUC
IQDF/PwAitcohl4lByxuqxJpSLJ5vueWq8US53/66RUREQIgMLInVDKCCoPHWDYM
vtFAmaxL8+rK+Hr55f0PLZQ5PcM=
-----END CERTIFICATE REQUEST-----
```

You can test if the CSR was created correctly here: [https://redkestrel.co.uk/products/decoder/](https://redkestrel.co.uk/products/decoder/)

## Requirements
- iOS 9+
- mac OS 10.12+

## Installation

CertificateSigningRequest is available through [CocoaPods](https://cocoapods.org). To install
it, simply add the following line to your Podfile:

```ruby
pod 'CertificateSigningRequest'
```

If you would like to use as a framework, clone and build the project, look under frameworks, and drag "CertificateSigningRequest.framework" into "Frameworks" section of your project, "check copy if needed".

- In your project Targets, click on "General", make sure "CertificateSigningRequest.framework" shows up under "Embedded Binaries" and it should automatically appear in "Linked Frameworks and Libraries"
- Then, simply place `import CertificateSigningRequest` at the top of any file that needs the framework.

## Author

cbaker6, coreyearleon@icloud.com

## License
Components of CertificateSigningRequest was originally in [ios-csr](https://github.com/ateska/ios-csr) by Ales Teska written in Objective-C and ported by the author of CertificateSigningRequest to Swift. Therefore CertificateSigningRequest has the same GPLv2 license. See the LICENSE file for more info.
