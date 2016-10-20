# iOS-csr-swift
Generate CSR (Certificate Signing Request) on iOS

This is a port of ios-csr by Ales Teska (https://github.com/ateska/ios-csr) from Objective-c to Swift 3.0. 
Additions have been made to allow SHA256 and SHA512. 

To use, initiatlize the class using one of the following: 
- let csr = CertificateSigningRequest()
- let csr = CertificateSigningRequest(cSecureHashAlgorithm: SecureHashAlgorithm)
- let csr = CertificateSigningRequest(cCommonName: String?, cOrganizationName:String?, cOrganizationUnitName:String?, cCountryName:String?, cSecureHashAlgorithm: SecureHashAlgorithm)

Then simply build your CSR using your publicKey(bits) and privateKey using, let csr = sccr.build(publicKeyBits, privateKey: privateKey).

Note: You will need to import CommonCrypto into your project. If you don't have this setup, follow the directions here: http://stackoverflow.com/questions/25248598/importing-commoncrypto-in-a-swift-framework?answertab=votes#tab-top


Feel free to use in your projects and contribute to this one.