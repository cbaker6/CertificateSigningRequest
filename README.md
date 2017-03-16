# iOSCSRSwift
Generate a certificate signing request (CSR) in iOS using Swift

This is a port of ios-csr by Ales Teska (https://github.com/ateska/ios-csr) from Objective-C to Swift 3.0 (a Swift 2.3 version is available on the 2.3 branch). 
Additions have been made to allow SHA256 and SHA512. 

To use, initiatlize the class using one of the following: 
- let csr = CertificateSigningRequest()
- let csr = CertificateSigningRequest(cryptoAlgorithm: CryptoAlgorithm)
- let csr = CertificateSigningRequest(commonName: String?, organizationName:String?, organizationUnitName:String?, countryName:String?, cryptoAlgorithm: CryptoAlgorithm)

Then simply build your CSR using your publicKey(bits) and privateKey using, let builtCSR = csr.build(publicKeyBits, privateKey: privateKey).

Note: You can get your publicKey in bit by querying it from the iOS keychain using String(kSecReturnData): kCFBooleanTrue in your query. 

Note2: If you use this as a framework, you will need to go to Targets->APPNAME->General and add "iOSCSRSwift.framework" to Embedded Binaries". You may need to add "CommonCrypto.framework" as well. If you just use want to use CertificateSigningRequest.swift you will need to import CommonCrypto into your project. To do this follow the directions here: http://stackoverflow.com/questions/25248598/importing-commoncrypto-in-a-swift-framework?answertab=votes#tab-top

Feel free to use in your projects and contribute to this one.
