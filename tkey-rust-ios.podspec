Pod::Spec.new do |spec|
  spec.name         = "tkey-rust-ios"
  spec.version      = "0.0.1"
  spec.platform = :ios, "15.0"
  spec.summary      = "SDK allows you to create threshold key setup natively"
  spec.homepage     = "https://github.com/torusresearch/tkey-rust-ios"
  spec.license      = { :type => 'BSD', :file  => 'License.md' }
  spec.swift_version   = "5.3"
  spec.author       = { "Torus Labs" => "rathishubham017@gmail.com" }
  spec.module_name = "tkey"
  spec.source       = { :git => "https://github.com/torusresearch/tkey-rust-ios.git", :tag => spec.version }

  spec.subspec "lib" do |spec|
    spec.source_files = "Sources/libtkey/bridge.c","Sources/libtkey/include/*.{h}"
    spec.vendored_frameworks = "Sources/libtkey/libtkey.xcframework"
  end
    
  spec.subspec "tkey" do |spec|
    spec.source_files = "Sources/ThresholdKey/*.{swift}","Sources/ThresholdKey/**/*.{swift}"
    spec.dependency "tkey-rust-ios/lib"
  end
end
