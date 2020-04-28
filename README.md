# CertificateSigningRequestSwift
![Swift Version 4.2](https://img.shields.io/badge/Swift-v5.0-yellow.svg)
[![CI Status](https://img.shields.io/travis/cbaker6/CertificateSigningRequestSwift.svg?style=flat)](https://travis-ci.org/cbaker6/CertificateSigningRequestSwift)
[![Version](https://img.shields.io/cocoapods/v/CertificateSigningRequestSwift.svg?style=flat)](https://cocoapods.org/pods/CertificateSigningRequestSwift)
[![License](https://img.shields.io/cocoapods/l/CertificateSigningRequestSwift.svg?style=flat)](https://cocoapods.org/pods/CertificateSigningRequestSwift)
[![Platform](https://img.shields.io/cocoapods/p/CertificateSigningRequestSwift.svg?style=flat)](https://cocoapods.org/pods/CertificateSigningRequestSwift)

Generate a certificate signing request (CSR) in iOS using Swift

This is a port of ios-csr by Ales Teska (https://github.com/ateska/ios-csr) from Objective-C to Swift 5.0 (a Swift 3.2 version is available on the "3.2" branch).
Additions have been made to support RSA and EC (iOS only supports 256 bit keys for now) allow SHA256 and SHA512. Also, this is setup to be added as a framework to your project.

To use, initiatlize the class using one of the following (an example of how to do can be found in the [test](https://github.com/cbaker6/CertificateSigningRequestSwift/blob/460e288156285e910af3181e0298a3aadd7f53a9/Example/Tests/Tests.swift#L19) file: 
- `let csr = CertificateSigningRequest()`
- `let csr = CertificateSigningRequest(keyAlgorithm: KeyAlgorithm)`
- `let csr = CertificateSigningRequest(commonName: String?, organizationName:String?, organizationUnitName:String?, countryName:String?, stateOrProvinceName:String?, localityName:String?, keyAlgorithm: KeyAlgorithm)`

Then simply build your CSR using your publicKey(bits) and privateKey using, `let builtCSR = csr.buildCSRAndReturnString(publicKeyBits, privateKey: privateKey)`.

Two other methods are available depending on your needs.

- To get CSR without header and footer info use: `let builtCSR = csr.buildAndEncodeDataAsString(publicKeyBits, privateKey: privateKey)`.
- To get CSR as Data use: `let builtCSR = csr.build(publicKeyBits, privateKey: privateKey)`.

Note1: To use out of the box, build the project, look under frameworks, and drag "CertificateSigningRequestSwift.framework" into your project. You will need to do this in two places:

- In your project Targets, click on "General"
- Place "CertificateSigningRequestSwift.framework" in "Embedded Binaries" and it should automatically appear in "Linked Frameworks and Libraries"
- Then, simply place "import CertificateSigningRequestSwift" at the top of any file that needs the framework.

Note2: You can get your publicKey in bit by querying it from the iOS keychain using `String(kSecReturnData): kCFBooleanTrue` in your query (see "testiOSKeyCreation()" in CertificateSigningRequestSwiftTests.swift).  An app to test the framework is available here: https://github.com/cbaker6/CertificateSigningRequestSwift_Test. Just run the test and the CSR will be printing in the debug window. You can test if the CSR was created correctly here: https://redkestrel.co.uk/products/decoder/

~~Note3: If you use this as a framework, you will need to go to Targets->APPNAME->General and add "CertificateSigningRequestSwift.framework" to Embedded Binaries". You may need to add "CommonCrypto.framework" as well. If you just use want to use CertificateSigningRequest.swift you will need to import CommonCrypto into your project. To do this follow the directions here: http://stackoverflow.com/questions/25248598/importing-commoncrypto-in-a-swift-framework?answertab=votes#tab-top~~

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

## Installation

CertificateSigningRequestSwift is available through [CocoaPods](https://cocoapods.org). To install
it, simply add the following line to your Podfile:

```ruby
pod 'CertificateSigningRequestSwift'
```

## Author

cbaker6, coreyearleon@icloud.com

## License

CertificateSigningRequestSwift is available under the MIT license. See the LICENSE file for more info.
