import Foundation
#if canImport(lib)
    import lib
#endif

public final class RssComm {
    private(set) var pointer: OpaquePointer?

    // This is a placeholder to satisfy the interface,
    // tracking this object is not necessary in swift as it maintains context
    // on entry for the callback
    private var obj_ref: UnsafeMutableRawPointer?

    public static func percentEscapeString(string: String) -> String {
        var characterSet = CharacterSet.alphanumerics
        characterSet.insert(charactersIn: "-.* ")

        return string
            .addingPercentEncoding(withAllowedCharacters: characterSet)!
            .replacingOccurrences(of: " ", with: "+")
            .replacingOccurrences(of: " ", with: "+", options: [], range: nil)
    }
    public init() throws {
        var errorCode: Int32 = -1

        let network_interface: (@convention(c) (UnsafeMutablePointer<CChar>?, UnsafeMutablePointer<CChar>?, UnsafeMutableRawPointer?, UnsafeMutablePointer<Int32>?) -> UnsafeMutablePointer<CChar>?)? = { url, data, _, error_code in
            let sem = DispatchSemaphore(value: 0)
            var urlString = String(cString: url!)
            let dataString = String(cString: data!)
            string_free(url)
            string_free(data)
            if urlString.split(separator: "/").last == "rss_round_2" {
                urlString.append("_stream") // use multipart-form api instead
            }
            let url = URL(string: urlString)!
            let session = URLSession.shared
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.addValue("*", forHTTPHeaderField: "Access-Control-Allow-Origin")
            request.addValue("GET, POST", forHTTPHeaderField: "Access-Control-Allow-Methods")
            request.addValue("Content-Type", forHTTPHeaderField: "Access-Control-Allow-Headers")
            if urlString.split(separator: "/").last == "rss_round_1" {
                request.addValue("application/json", forHTTPHeaderField: "Content-Type")
                request.httpBody = dataString.data(using: String.Encoding.utf8)
                var resultPointer = UnsafeMutablePointer<CChar>(nil)
                var result = NSString()
                session.dataTask(with: request) { data, _, error in
                    defer {
                        sem.signal()
                    }
                    if error != nil {
                        let code: Int32 = 1
                        error_code?.pointee = code
                    }
                    if let data = data {
                        let resultString: String = String(decoding: data, as: UTF8.self)
                        result = NSString(string: resultString)
                    }
                }.resume()
                
                sem.wait()
                resultPointer = UnsafeMutablePointer<CChar>(mutating: result.utf8String)
                return resultPointer
            } else {
                let json = try! JSONSerialization.jsonObject(with: dataString.data(using: String.Encoding.utf8)!, options: .allowFragments) as! [String: Any]
                
                let boundary = "Boundary-\(UUID().uuidString)"
                var request = URLRequest(url: url)
                request.httpMethod = "POST"
                request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
                
                var body = Data()
                
                func appendField(name: String, value: Any) {
                    body.append("--\(boundary)\r\n".data(using: .utf8)!)
                    body.append("Content-Disposition: form-data; name=\"\(name)\"\r\n\r\n".data(using: .utf8)!)
                    body.append("\(value)\r\n".data(using: .utf8)!)
                }
                
                func appendJSONField(name: String, json: Any) {
                    if let jsonData = try? JSONSerialization.data(withJSONObject: json, options: []),
                       let jsonString = String(data: jsonData, encoding: .utf8) {
                        body.append("--\(boundary)\r\n".data(using: .utf8)!)
                        body.append("Content-Disposition: form-data; name=\"\(name)\"\r\n".data(using: .utf8)!)
                        body.append("Content-Type: application/json\r\n\r\n".data(using: .utf8)!)
                        body.append("\(jsonString)\r\n".data(using: .utf8)!)
                    }
                }
                
                if let roundName = json["round_name"] as? String {
                    appendField(name: "round_name", value: roundName)
                }
                if let serverIndex = json["server_index"] as? Int {
                    appendField(name: "server_index", value: serverIndex)
                }
                if let targetIndex = json["target_index"] as? [Int] {
                    appendField(name: "target_index", value: targetIndex.map { "\($0)" }.joined(separator: ","))
                }
                
                if let data = json["data"] as? [[String: Any]] {
                    for (index, dataItem) in data.enumerated() {
                        if let masterCommits = dataItem["master_commits"] as? [[String: Any]] {
                            for (idx, subDataItem) in masterCommits.enumerated() {
                                appendJSONField(name: "data[\(index)][master_commits[\(idx)]]", json: subDataItem)
                            }
                        }
                        if let serverCommits = dataItem["server_commits"] as? [[String: Any]] {
                            for (idx, subDataItem) in serverCommits.enumerated() {
                                appendJSONField(name: "data[\(index)][server_commits[\(idx)]]", json: subDataItem)
                            }
                        }
                        if let serverEncs = dataItem["server_encs"] as? [[String: Any]] {
                            for (idx, subDataItem) in serverEncs.enumerated() {
                                appendJSONField(name: "data[\(index)][server_encs[\(idx)]]", json: subDataItem)
                            }
                        }
                        if let factorPubkeys = dataItem["factor_pubkeys"] as? [[String: Any]] {
                            for (idx, subDataItem) in factorPubkeys.enumerated() {
                                appendJSONField(name: "data[\(index)][factor_pubkeys[\(idx)]]", json: subDataItem)
                            }
                        }
                    }
                }
                
                body.append("--\(boundary)--\r\n".data(using: .utf8)!)
                request.httpBody = body
                var resultPointer = UnsafeMutablePointer<CChar>(nil)
                var result = NSString()
                session.dataTask(with: request) { data, _, error in
                    defer {
                        sem.signal()
                    }
                    if error != nil {
                        let code: Int32 = 1
                        error_code?.pointee = code
                    }
                    if let data = data {
                        let resultString: String = String(decoding: data, as: UTF8.self)
                        result = NSString(string: resultString)
                    }
                }.resume()
                
                sem.wait()
                resultPointer = UnsafeMutablePointer<CChar>(mutating: result.utf8String)
                return resultPointer
            }
        }

        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            rss_comm(network_interface, obj_ref, error)
        })
        guard errorCode == 0 else {
            throw RuntimeError("Error in RssComm")
        }
        pointer = result
    }

    deinit {
        let _ = rss_comm_free(pointer)
    }
}
