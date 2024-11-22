import XCTest
import Foundation
import tkey

final class tkey_pkgVersionTests: XCTestCase {
    func test_library_version() {
        _ = try! library_version()
    }
}
