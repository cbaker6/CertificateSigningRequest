#
# Be sure to run `pod lib lint CertificateSigningRequest.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'CertificateSigningRequest'
  s.version          = '1.29.0'
  s.summary          = 'Generate self-signed certificate signing requests (CSRs) on iOS, macOS, macCatalyst, watchOS, and tvOS.'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = <<-DESC
  Enables your app to create self-signed CSRs directly on iOS devices. These CSRs can then be sent somewhere else and turned into certificates. The framework should also work on macCatalyst and macOS 10.12+, assuming the keys are created correctly (the test cases shows how to create keys using the iOS Keychain).
                       DESC

  s.homepage         = 'https://github.com/cbaker6/CertificateSigningRequest'
  # s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
  s.license          = { :type => 'GPLv2', :file => 'LICENSE' }
  s.author           = { 'cbaker6' => 'coreyearleon@icloud.com' }
  s.source           = { :git => 'https://github.com/cbaker6/CertificateSigningRequest.git', :tag => s.version.to_s }
  # s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

  s.ios.deployment_target  = '13.0'
  s.osx.deployment_target  = '10.15'
  s.tvos.deployment_target  = '13.0'
  s.watchos.deployment_target  = '6.0'
  s.swift_versions = ['4.0', '5.0', '5.1', '5.2', '5.3', '5.4', '5.5', '5.6']
  s.source_files = 'Sources/CertificateSigningRequest/**/*.swift'
  
  # s.resource_bundles = {
  #   'CertificateSigningRequest' => ['CertificateSigningRequest/Assets/*.png']
  # }

  # s.public_header_files = 'Pod/Classes/**/*.h'
  # s.frameworks = 'UIKit', 'MapKit'
  # s.dependency 'AFNetworking', '~> 2.3'
end
