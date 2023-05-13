#
# Be sure to run `pod lib lint CertificateSigningRequest.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'CertificateSigningRequest'
  s.version          = '1.30.0'
  s.summary          = 'Generate self-signed certificate signing requests (CSRs) on iOS, macOS, macCatalyst, watchOS, and tvOS.'

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
  s.swift_versions = ['5.5', '5.6', '5.7', '5.8']
  s.source_files = 'Sources/CertificateSigningRequest/**/*.swift'
end
