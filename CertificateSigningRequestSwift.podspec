Pod::Spec.new do |s|

  s.name         = "CertificateSigningRequestSwift"
  s.version      = "0.0.992"
  s.summary      = "Generate a self-signed certificate signing request (CSR) in iOS using Swift"

  s.description  = <<-DESC 
  	CertificateSigningRequest creates a self-signed CSR's directly an iOS devices
                   DESC

  s.homepage     = "https://github.com/cbaker6/CertificateSigningRequestSwift"
  s.license      = { :type => "MIT", :file => "LICENSE" }
  s.author             = { "Corey Baker" => "coreyearleon@icloud.com" }
  s.platform     = :ios, "9.3"

  s.source       = { :git => "https://github.com/cbaker6/CertificateSigningRequestSwift.git", :tag => "#{s.version}" }


  s.source_files  = "CertificateSigningRequestSwift" #, "CertificateSigningRequestSwift/**/*.{h,m,swift}", "CommonCrypto/**/*.{c,h}"
  #s.exclude_files = "iOS-csr-swift/Exclude"

  # s.public_header_files = "Classes/**/*.h"
  # s.private_header_files = "CommonCrypto/**/*.{c,h}"

  # s.pod_target_xcconfig = { 'SWIFT_VERSION' => '3', 'SWIFT_INCLUDE_PATHS' => 'CommonCrypto/Platforms/**' }
  s.pod_target_xcconfig = { 
	'SWIFT_VERSION' 				=> '4'#,
	#'SWIFT_INCLUDE_PATHS[sdk=iphoneos*]' 		=> 'CommonCrypto/ iPhoneOS/**', 
	#'SWIFT_INCLUDE_PATHS[sdk=iphonesimulator*]' 	=> 'CommonCrypto/Platforms/iPhoneSimulator/**',
	#'SWIFT_INCLUDE_PATHS[sdk=macosx*]' 		=> 'CommonCrypto/Platforms/MacOSX/**'
  }	
  # s.resource  = "icon.png"
  # s.resources = "Resources/*.png"

  # s.preserve_paths = "FilesToSave", "MoreFilesToSave"
  s.preserve_paths = "CommonCrypto/iphoneos.private.modulemap", "CommonCrypto/iphonesimulator.private.modulemap", "CommonCrypto/macos.private.modulemap"

  # s.framework  = "SomeFramework"
  # s.frameworks = "SomeFramework", "AnotherFramework"

  # s.library   = "iconv"
  # s.libraries = "iconv", "xml2"

  # s.xcconfig = { "HEADER_SEARCH_PATHS" => "$(SDKROOT)/usr/include/libxml2" }
  # s.dependency "JSONKit", "~> 1.4"

end
