# CertificateSigningRequest
[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fcbaker6%2FCertificateSigningRequest%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/cbaker6/CertificateSigningRequest)
[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fcbaker6%2FCertificateSigningRequest%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/cbaker6/CertificateSigningRequest)
[![CI Status](https://github.com/cbaker6/CertificateSigningRequest/workflows/build/badge.svg?branch=main)](https://github.com/cbaker6/CertificateSigningRequest/actions?query=workflow%3Abuild+branch%3Amain)
[![Codecov](https://codecov.io/gh/cbaker6/CertificateSigningRequest/branches/main/graph/badge.svg)](https://codecov.io/gh/cbaker6/CertificateSigningRequest/branches/main)
[![SPM](https://img.shields.io/badge/swift%20package%20manager-compatible-brightgreen.svg)](https://github.com/apple/swift-package-manager)
[![Version](https://img.shields.io/cocoapods/v/CertificateSigningRequest.svg?style=flat)](https://cocoapods.org/pods/CertificateSigningRequest)
[![License](https://img.shields.io/cocoapods/l/CertificateSigningRequest.svg?style=flat)](https://cocoapods.org/pods/CertificateSigningRequest)

Generate a certificate signing request (CSR) in iOS/macOS using Swift.

## iOS
Supports RSA (key size: 512, 1024, 2048) and EC inside/outside of secure enclave (iOS only supports 256 bit keys for now), SHA1, SHA256, and SHA512. 

## macOS
Supports RSA (key size: 1024, 2048) and EC inside/outside of secure enclave, SHA1, SHA256, and SHA512. 

## Usage

To use, follow the following steps:

1. Generate your publicKey/privateKey pair. This can be done using Keychain in iOS. An example can be found in the `generateKeysAndStoreInKeychain` function in the [testfile](https://github.com/cbaker6/CertificateSigningRequest/blob/main/Example/Tests/Tests.swift#L440).
2.  Get your publicKey in bits by querying it from the iOS keychain using `String(kSecReturnData): true` in your query. For example:

```swift
//Set block size
let keyBlockSize = SecKeyGetBlockSize(publicKey)
//Ask keychain to provide the publicKey in bits
let query: [String: Any] = [
    String(kSecClass): kSecClassKey,
    String(kSecAttrKeyType): algorithm.secKeyAttrType,
    String(kSecAttrApplicationTag): tagPublic.data(using: .utf8)!,
    String(kSecReturnData): true
]

var tempPublicKeyBits:CFTypeRef?
var _ = SecItemCopyMatching(query as CFDictionary, &tempPublicKeyBits)

guard let keyBits = tempPublicKeyBits as? Data else {
    return (nil,nil)
}
```
3. Initiatlize the `CertificateSigningRequest` using `KeyAlgorithm.ec` or `KeyAlgorithm.rsa` (an example of how to do can be found in the [test](https://github.com/cbaker6/CertificateSigningRequest/blob/main/Example/Tests/Tests.swift#L34) file. Below are 3 possible ways to initialize: 
```swift 
let csr = CertificateSigningRequest() //CSR with no fields, will use defaults of an RSA key with sha512
let algorithm = KeyAlgorithm.ec(signatureType: .sha256)
let csr = CertificateSigningRequest(keyAlgorithm: algorithm) //CSR with a specific key 
let csr = CertificateSigningRequest(commonName: String?, organizationName: String?, organizationUnitName: String?, countryName: String?, stateOrProvinceName: String?, localityName: String?, emailAddress: String?, description: String?, keyAlgorithm: algorithm) //Define any field you want in your CSR along with the key algorithm
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

You can test if your CSRs are correct by running and setting a break point the [test file](https://github.com/cbaker6/CertificateSigningRequest/blob/main/Example/Tests/Tests.swift#L66). You can also let all test run and test the different CSR's. The output of the CSR will print in the console window. You can output the CSR's and your own app by printing to the console and check if they are created correctly by pasting them here: https://redkestrel.co.uk/products/decoder/ or by using openssl.

## Example

To run the example project, clone the repo, and run `pod install` from the Example directory first. An example certificate from this framework is below:

```
-----BEGIN CERTIFICATE REQUEST-----
MIIBYTCCAQcCAQAwgaQxCzAJBgNVBAYMAlVTMQswCQYDVQQIDAJLWTENMAsGA1UE
BwwEVGVzdDENMAsGA1UECgwEVGVzdDENMAsGA1UECwwEVGVzdDEnMCUGA1UEAwwe
Q2VydGlmaWNhdGVTaWduaW5nUmVxdWVzdCBUZXN0MSIwIAYJKoZIhvcNAQkBDBNu
ZXRyZWNvbkBjcy51a3kuZWR1MQ4wDAYDVQQNDAVoZWxsbzBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABN5Wp7zEAVkffuqmkC22j3mOCJalTo2Beff23N8Bv7sZ0iTM
AdqeeF+A1fAO5yUwykbTYhAyNiwkT82jtOy09xKgADAKBggqhkjOPQQDAgNIADBF
AiEAt85IAQ9kOptiplqYkLyRz4is/uB4DffNpWuP9EUJY74CIHtjMZ6QRwY1zPGI
bXC5eX6Kpv5QLfvR6xX7Xqaoy6Ai
-----END CERTIFICATE REQUEST-----
```

You can test if the CSR was created correctly here: [https://redkestrel.co.uk/products/decoder/](https://redkestrel.co.uk/products/decoder/)

## Requirements
- iOS 10+
- mac OS 10.13+

## Installation

### Swift Package Manager (SPM) - Option 1
CertificateSigningRequest can be installed via SPM. Open an existing project or create a new Xcode project and navigate to `File > Swift Packages > Add Package Dependency`. Enter the url `https://github.com/cbaker6/CertificateSigningRequest.git` and tap `Next`. Choose the main branch, and on the next screen, check off the package.

### Cocoapods - Option 2
CertificateSigningRequest is available through [CocoaPods](https://cocoapods.org). To install
it, simply add the following line to your Podfile:

```ruby
pod 'CertificateSigningRequest'
```

### Embedded Framework - Option 3
If you would like to use as a framework, clone and build the project, look under frameworks, and drag "CertificateSigningRequest.framework" into "Frameworks" section of your project, "check copy if needed".

- In your project Targets, click on "General", make sure "CertificateSigningRequest.framework" shows up under "Embedded Binaries" and it should automatically appear in "Linked Frameworks and Libraries"
- Then, simply place `import CertificateSigningRequest` at the top of any file that needs the framework.

## Author

cbaker6, coreyearleon@icloud.com

## License
Components of CertificateSigningRequest was originally in [ios-csr](https://github.com/ateska/ios-csr) by Ales Teska written in Objective-C and ported by the author of CertificateSigningRequest to Swift. Therefore CertificateSigningRequest has the same GPLv2 license. See the LICENSE file for more info.
