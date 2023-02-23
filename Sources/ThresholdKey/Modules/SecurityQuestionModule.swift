//
//  SecurityQuestionModule.swift
//  tkey_ios
//
//  Created by David Main.
//

import Foundation
#if canImport(lib)
    import lib
#endif

public final class SecurityQuestionModule {
    private static func generate_new_share(threshold_key: ThresholdKey, questions: String, answer: String) throws -> GenerateShareStoreResult {
        var errorCode: Int32 = -1
        let curvePointer = UnsafeMutablePointer<Int8>(mutating: (threshold_key.curveN as NSString).utf8String)
        let questionsPointer = UnsafeMutablePointer<Int8>(mutating: (questions as NSString).utf8String)
        let answerPointer = UnsafeMutablePointer<Int8>(mutating: (answer as NSString).utf8String)
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            security_question_generate_new_share(threshold_key.pointer, questionsPointer, answerPointer, curvePointer, error)
                })
        guard errorCode == 0 else {
            throw RuntimeError("Error in SecurityQuestionModule, generate_new_share")
            }
        return try! GenerateShareStoreResult.init(pointer: result!)
    }
    
    private static func generate_new_share(threshold_key: ThresholdKey, questions: String, answer: String, completion: @escaping (Result<GenerateShareStoreResult, Error>) -> Void) {
        threshold_key.tkeyQueue.async {
            do {
                let result = try generate_new_share(threshold_key: threshold_key, questions: questions, answer: answer)
                completion(.success(result))
            } catch {
                completion(.failure(error))
            }
        }
    }
    
    public static func generate_new_share(threshold_key: ThresholdKey, questions: String, answer: String ) async throws -> GenerateShareStoreResult {
        return try await withCheckedThrowingContinuation {
            continuation in
            generate_new_share(threshold_key: threshold_key, questions: questions, answer: answer) {
                result in
                switch result {
                case .success(let result):
                    continuation.resume(returning: result)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }
    
    private static func input_share(threshold_key: ThresholdKey, answer: String) throws -> Bool {
        var errorCode: Int32 = -1
        let curvePointer = UnsafeMutablePointer<Int8>(mutating: (threshold_key.curveN as NSString).utf8String)
        let answerPointer = UnsafeMutablePointer<Int8>(mutating: (answer as NSString).utf8String)
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            security_question_input_share(threshold_key.pointer, answerPointer, curvePointer, error)
                })
        guard errorCode == 0 else {
            throw RuntimeError("Error in SecurityQuestionModule, input_share")
            }
        return result
    }
    
    private static func input_share(threshold_key: ThresholdKey, answer: String, completion: @escaping (Result<Bool, Error>) -> Void) {
        threshold_key.tkeyQueue.async {
            do {
                let result = try input_share(threshold_key: threshold_key, answer: answer)
                completion(.success(result))
            } catch {
                completion(.failure(error))
            }
        }
    }
    
    public static func input_share(threshold_key: ThresholdKey, answer: String ) async throws -> Bool {
        return try await withCheckedThrowingContinuation {
            continuation in
            input_share(threshold_key: threshold_key, answer: answer) {
                result in
                switch result {
                case .success(let result):
                    continuation.resume(returning: result)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private static func change_question_and_answer(threshold_key: ThresholdKey, questions: String, answer: String) throws -> Bool {
        var errorCode: Int32 = -1
        let curvePointer = UnsafeMutablePointer<Int8>(mutating: (threshold_key.curveN as NSString).utf8String)
        let questionsPointer = UnsafeMutablePointer<Int8>(mutating: (questions as NSString).utf8String)
        let answerPointer = UnsafeMutablePointer<Int8>(mutating: (answer as NSString).utf8String)
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            security_question_change_question_and_answer(threshold_key.pointer, questionsPointer, answerPointer, curvePointer, error)
                })
        guard errorCode == 0 else {
            throw RuntimeError("Error in SecurityQuestionModule, change_question_and_answer")
            }
        return result
    }
    
    private static func change_question_and_answer(threshold_key: ThresholdKey, questions: String, answer: String, completion: @escaping (Result<Bool, Error>) -> Void) {
        threshold_key.tkeyQueue.async {
            do {
                let result = try change_question_and_answer(threshold_key: threshold_key, questions: questions, answer: answer)
                completion(.success(result))
            } catch {
                completion(.failure(error))
            }
        }
    }
    
    public static func change_question_and_answer(threshold_key: ThresholdKey, questions: String, answer: String ) async throws -> Bool {
        return try await withCheckedThrowingContinuation {
            continuation in
            change_question_and_answer(threshold_key: threshold_key, questions: questions, answer: answer) {
                result in
                switch result {
                case .success(let result):
                    continuation.resume(returning: result)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }
    
    private static func store_answer(threshold_key: ThresholdKey, answer: String) throws -> Bool {
        var errorCode: Int32 = -1
        let curvePointer = UnsafeMutablePointer<Int8>(mutating: (threshold_key.curveN as NSString).utf8String)
        let answerPointer = UnsafeMutablePointer<Int8>(mutating: (answer as NSString).utf8String)
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            security_question_store_answer(threshold_key.pointer, answerPointer, curvePointer, error)
                })
        guard errorCode == 0 else {
            throw RuntimeError("Error in SecurityQuestionModule, change_question_and_answer")
            }
        return result
    }
    
    private static func store_answer(threshold_key: ThresholdKey, answer: String, completion: @escaping (Result<Bool, Error>) -> Void) {
        threshold_key.tkeyQueue.async {
            do {
                let result = try store_answer(threshold_key: threshold_key, answer: answer)
                completion(.success(result))
            } catch {
                completion(.failure(error))
            }
        }
    }
    
    public static func store_answer(threshold_key: ThresholdKey, answer: String ) async throws -> Bool {
        return try await withCheckedThrowingContinuation {
            continuation in
            store_answer(threshold_key: threshold_key, answer: answer) {
                result in
                switch result {
                case .success(let result):
                    continuation.resume(returning: result)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    public static func get_answer(threshold_key: ThresholdKey) throws -> String {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            security_question_get_answer(threshold_key.pointer, error)
                })
        guard errorCode == 0 else {
            throw RuntimeError("Error in SecurityQuestionModule, change_question_and_answer")
            }
        let string = String.init(cString: result!)
        string_free(result)
        return string
    }

    public static func get_questions(threshold_key: ThresholdKey) throws -> String {
        var errorCode: Int32 = -1
        let result = withUnsafeMutablePointer(to: &errorCode, { error in
            security_question_get_questions(threshold_key.pointer, error)
                })
        guard errorCode == 0 else {
            throw RuntimeError("Error in SecurityQuestionModule, change_question_and_answer")
            }
        let string = String.init(cString: result!)
        string_free(result)
        return string
    }
}