#
# Be sure to run `pod lib lint CertificateSigningRequestSwift.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'CertificateSigningRequestSwift'
  s.version          = '1.0'
  s.summary          = 'Generate a self-signed certificate signing request (CSR) in iOS using Swift'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = <<-DESC
CertificateSigningRequest creates a self-signed CSRs directly an iOS devices
                       DESC

  s.homepage         = 'https://github.com/cbaker6/CertificateSigningRequestSwift'
  # s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
  s.license          = { :type => 'GNU', :file => 'LICENSE' }
  s.author           = { 'cbaker6' => 'coreyearleon@icloud.com' }
  s.source           = { :git => 'https://github.com/cbaker6/CertificateSigningRequestSwift.git', :tag => s.version.to_s }
  # s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

  s.ios.deployment_target  = '9.3'
  s.osx.deployment_target  = '10.12'
  s.swift_versions = ['4.0', '5.0']
  s.source_files = 'CertificateSigningRequestSwift/Classes/**/*'
  
  # s.resource_bundles = {
  #   'CertificateSigningRequestSwift' => ['CertificateSigningRequestSwift/Assets/*.png']
  # }

  # s.public_header_files = 'Pod/Classes/**/*.h'
  # s.frameworks = 'UIKit', 'MapKit'
  # s.dependency 'AFNetworking', '~> 2.3'
end
