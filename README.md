# iOSCSRSwift
Generate a certificate signing request (CSR) in iOS using Swift

This is a port of ios-csr by Ales Teska (https://github.com/ateska/ios-csr) from Objective-C to Swift 3.0 (a Swift 2.3 version is available on the 2.3 branch). 
Additions have been made to allow SHA256 and SHA512. Also, this is setup to be added as a framework to your project.

To use, initiatlize the class using one of the following (an example of how to do can be found at https://github.com/cbaker6/iOSCSRSwift/blob/master/iOSCSRSwiftTests/iOSCSRSwiftTests.swift): 
- let csr = CertificateSigningRequest()
- let csr = CertificateSigningRequest(cryptoAlgorithm: CryptoAlgorithm)
- let csr = CertificateSigningRequest(commonName: String?, organizationName:String?, organizationUnitName:String?, countryName:String?, cryptoAlgorithm: CryptoAlgorithm)

Then simply build your CSR using your publicKey(bits) and privateKey using, let builtCSR = csr.build(publicKeyBits, privateKey: privateKey).

Note1: To use out of the box, build the project, look under frameworks, and drag "iOSCSRSwift.framework" into your project. You will need to do this in two places:

- In your project Targets, click on "General"
- Place "iOSCSRSwift.framework" in "Embedded Binaries" and "Linked Frameworks and Libraries"
- Then, simply place import iOSCSRSwift at the top of any file that needs the framework.

Note2: You can get your publicKey in bit by querying it from the iOS keychain using String(kSecReturnData): kCFBooleanTrue in your query (see "setUp()" in iOSCSRSwiftTests.swift). 

Note3: Do not try to run the testcase from within the framework, it **WILL FAIL**. I believe this is because a framework doesn't have the same entitlements as an application and therefore doesn't have access to a keychain. You should be able to run the testcase by copy/pasting it inside of your own application unit test.

~~Note4: If you use this as a framework, you will need to go to Targets->APPNAME->General and add "iOSCSRSwift.framework" to Embedded Binaries". You may need to add "CommonCrypto.framework" as well. If you just use want to use CertificateSigningRequest.swift you will need to import CommonCrypto into your project. To do this follow the directions here: http://stackoverflow.com/questions/25248598/importing-commoncrypto-in-a-swift-framework?answertab=votes#tab-top~~

**If anyone would like to help prepare this project for cocoapods, I could use your help. Please see the "testingCocoaPods" branch. I currently can't get the project to pass lint.**

Feel free to use in your projects and contribute to this one.
