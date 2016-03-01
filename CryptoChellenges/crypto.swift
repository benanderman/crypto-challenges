//
//  crypto.swift
//  CryptoChellenges
//
//  Created by Ben Anderman on 2/10/16.
//  Copyright © 2016 Ben Anderman. All rights reserved.
//

import Foundation

struct Crypto {
  
  enum AsciiRange: Int {
    case Lower, Upper, Space, Symbol, Bad, Other
    init(value: UInt8) {
      switch value {
      case 97 ... 122:
          self = Lower
      case 65 ... 91:
          self = Upper
      case 32:
          self = Space
      case (33 ... 47), (58 ... 64), (91 ... 96), (123 ... 126):
          self = Symbol
      case (0 ..< 10), 11, 12, (14 ... 31), (127 ..< 255):
          self = Bad
      default:
        self = Other
      }
    }
  }
  
  static func hexToBase64(hex: String) -> String? {
    return hex.bytesFromHex?.base64Representation
  }
  
  static func xorHexStrings(hex1: String, hex2: String) -> String? {
    guard hex1.utf8.count == hex2.utf8.count else {return nil}
    guard let bytes1 = hex1.bytesFromHex, let bytes2 = hex2.bytesFromHex else {return nil}
    let result = (0 ..< bytes1.count).map{ bytes1[$0] ^ bytes2[$0] }
    return result.hexStringRepresentation
  }
  
  static func xorData(data1: [UInt8], data2: [UInt8]) -> [UInt8]? {
    guard data1.count == data2.count else {return nil}
    return (0 ..< data1.count).map{ data1[$0] ^ data2[$0] }
  }
  
  static func findBestHammingDistance(data: [UInt8], range: Range<Int>) -> Int {
    var keySize = 0
    var bestEditDistance = Double.infinity
    for i in range {
      var distances:[Double] = [Double]()
      for o in data.startIndex.stride(to: data.endIndex - i * 2, by: i) {
        let data1 = [UInt8](data[o ..< o + i])
        let data2 = [UInt8](data[o + i ..< o + i * 2])
        let distance = hammingDistance(data1, data2: data2)
        let normalizedDistance = Double(distance) / Double(i * 8)
        distances.append(normalizedDistance)
      }
      let distance = distances.reduce(0) { $0 + $1 } / Double(distances.count)
      if (distance < bestEditDistance) {
        bestEditDistance = distance
        keySize = i
      }
    }
    return keySize
  }
  
  static func decipherRepeatingKeyXorBase64(base64: String) -> (result: String, key: [UInt8])? {
    guard let bytes = base64.bytesFromBase64 else {return nil}
    let keySize = findBestHammingDistance(bytes, range: 2 ... 40)
    
    var blocks = [[UInt8]]()
    var key = [UInt8]()
    for i in 0 ..< keySize {
      let block = i.stride(to: bytes.count, by: keySize).map { bytes[$0] }
      let decoded = decipherSingleByteXor(block)
      blocks.append(decoded.result)
      key.append(decoded.key)
    }
    
    if (blocks.count == 0) {
      return nil
    }
    var result = [UInt8]()
    for i in 0 ..< blocks.first!.count {
      for block in blocks {
        if i < block.count {
          result.append(block[i])
        }
      }
    }
    return (result.stringRepresentation, key)
  }
  
  static func decipherSingleByteXor(input: [UInt8]) -> (result: [UInt8], key: UInt8, score: Int) {
    var bestScore = Int.min
    var bestResult = [UInt8]()
    var bestKey = 0 as UInt8
    for i in 0 ..< 256 {
      let deciphered = decipherSingleByteXor(input, key: UInt8(i))
      let score = textScoreForData(deciphered)
      if (score > bestScore) {
        bestScore = score
        bestResult = deciphered
        bestKey = UInt8(i)
      }
    }
    return (bestResult, bestKey, bestScore)
  }
  
  static func decipherSingleByteXorHex(inputs: [String]) -> String? {
    var bestScore = Int.min
    var bestResult = [UInt8]()
    for input in inputs {
      guard let bytes = input.bytesFromHex else {return nil}
      let (result, _, score) = decipherSingleByteXor(bytes)
      if (score > bestScore) {
        (bestResult, bestScore) = (result, score)
      }
    }
    return bestResult.stringRepresentation
  }
  
  static func textScoreForData(data: [UInt8]) -> Int {
    guard !data.isEmpty else { return Int.min }
    
    var counts: Dictionary<AsciiRange, Int> = Dictionary<AsciiRange, Int>()
    for char in data {
      let range = AsciiRange(value: char)
      if let count = counts[range] {
        counts[range] = count + 1
      } else {
        counts[range] = 1
      }
    }
    
    var score = 0
    let lowerCount = counts[AsciiRange.Lower] ?? 0
    let upperCount = counts[AsciiRange.Upper] ?? 0
    let spaceCount = counts[AsciiRange.Space] ?? 0
    let symbolCount = counts[AsciiRange.Symbol] ?? 0
    let badCount = counts[AsciiRange.Bad] ?? 0
    
    score += Int((1 - abs(Double(lowerCount) / Double(data.count) - 0.75)) * 300)
    score += Int((1 - abs(Double(upperCount) / Double(data.count) - 0.2)) * 50)
    let spaceRatio = Double(spaceCount) / Double(data.count)
    score += Int((1 - abs(spaceRatio - 0.17)) * 100)
    if spaceRatio > 0 && spaceRatio < 0.5 {
      score += 500
    }
    let symbolRatio = Double(symbolCount) / Double(data.count)
    if symbolRatio > 0.5 {
      score -= Int(symbolRatio * Double(900))
    }
    
    score += Int(Double(badCount) / Double(data.count) * -900)
    
    return score
  }
  
  static func encryptAES128ECB(input: [UInt8]) -> [UInt8] {
    return encryptAES128ECB(input, key: randomBytes(16))
  }
  
  static func encryptAES128ECB(input: [UInt8], key: [UInt8]) -> [UInt8] {
    var bytes = padUsingPKCS7(input, multiple: 16)
    var enc_key: AES_KEY = AES_KEY()
    AES_set_encrypt_key(key, 128, &enc_key)
    
    var result = [UInt8](count: bytes.count, repeatedValue: 0)
    for i in 0.stride(to: bytes.count, by: 16) {
      AES_ecb_encrypt(&bytes + i, &result + i, &enc_key, AES_ENCRYPT)
    }
    return result
  }
  
  static func decryptAES128(var bytes: [UInt8], key: [UInt8]) -> [UInt8]? {
    guard bytes.count % 16 == 0 else { return nil }
    
    // Fixes a linker error caused by an OpenSSL bug with static libraries
    OPENSSL_cleanse(nil, 0)
    
    var dec_key: AES_KEY = AES_KEY()
    AES_set_decrypt_key(key, 128, &dec_key)
    var result = [UInt8](count: bytes.count, repeatedValue: 0)
    for i in 0.stride(to: bytes.count, by: 16) {
      AES_ecb_encrypt(&bytes + i, &result + i, &dec_key, AES_DECRYPT)
    }
    return result
  }
  
  static func encryptAES128CBC(input: [UInt8]) -> [UInt8] {
    return encryptAES128CBC(input, key: randomBytes(16), iv: randomBytes(16))
  }
  
  static func encryptAES128CBC(input: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8] {
    var bytes = padUsingPKCS7(input, multiple: 16)
    var enc_key: AES_KEY = AES_KEY()
    AES_set_encrypt_key(key, 128, &enc_key)
    
    var lastBlock = iv
    var result = [UInt8](count: bytes.count, repeatedValue: 0)
    for i in 0.stride(to: bytes.count, by: 16) {
      let xored = (0 ..< 16).map{ bytes[i + $0] ^ lastBlock[$0] }
      bytes.replaceRange(i ..< i + 16, with: xored)
      AES_ecb_encrypt(&bytes + i, &result + i, &enc_key, AES_ENCRYPT)
      lastBlock = [UInt8](result[i ..< i + 16])
    }
    return result
  }
  
  static func decryptAES128CBC(bytes: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8]? {
    guard bytes.count % 16 == 0 else { return nil }
    guard var decoded = decryptAES128(bytes, key: key) where decoded.count == bytes.count else { return nil }
    
    var xorWith = iv
    for i in 0.stride(to: bytes.count, by: 16) {
      let range = i ..< i + 16
      guard let xored = xorData([UInt8](decoded[range]), data2: xorWith) else { return nil }
      decoded.replaceRange(range, with: xored)
      xorWith = [UInt8](bytes[range])
    }
    
    return decoded
  }
  
  static func encryptAES128Random(var input: [UInt8]) -> (result: [UInt8], usedCBC: Bool) {
    let prefix  = randomBytes(5 + Int(arc4random_uniform(UInt32(6))))
    let postfix = randomBytes(5 + Int(arc4random_uniform(UInt32(6))))
    input = prefix + input + postfix
    if UInt8(arc4random_uniform(UInt32(2))) == 1 {
      return (encryptAES128CBC(input), true)
    } else {
      return (encryptAES128ECB(input), false)
    }
  }
  
  static let staticKey = Crypto.randomBytes(16)
  static let postfix = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK".bytesFromBase64
  static func encryptAES128RandomStaticECB(var input: [UInt8]) -> [UInt8] {
    guard postfix != nil else { fatalError() }
    input = input + postfix!
    return encryptAES128ECB(input, key: staticKey)
  }
  
  static func detectAES128Hex(inputs: [String]) -> String? {
    var mostHits = 0
    var result: String? = nil
    for data in inputs {
      guard data.utf8.count % 32 == 0 else { continue }
      var hits = 0
      var blocks: Set<String> = []
      for var i = data.startIndex; i != data.endIndex; i = i.advancedBy(32) {
        let block = data.substringWithRange(i ..< i.advancedBy(32))
        if blocks.contains(block) {
          hits++
        } else {
          blocks.insert(block)
        }
      }
      if hits > mostHits {
        result = data
        mostHits = hits
      }
    }
    return result
  }
  
  static func padUsingPKCS7(var data: [UInt8], multiple: UInt8) -> [UInt8] {
    let padding = Int(multiple) - (data.count % Int(multiple));
    data += [UInt8](count: padding, repeatedValue: UInt8(padding))
    return data
  }
  
  static func decipherSingleByteXor(data: [UInt8], key: UInt8) -> [UInt8] {
    return data.map { $0 ^ key }
  }
  
  static func cipherStringWithKey(string: String, key: [UInt8]) -> String {
    return string.bytes.enumerate().map({ (index: Int, byte: UInt8) in
      return byte ^ key[index % key.count]
    }).hexStringRepresentation
  }
  
  static func randomBytes(count: Int) -> [UInt8] {
    return (0 ..< count).map { _ in UInt8(arc4random_uniform(UInt32(UInt8.max))) }
  }
  
  static func hammingDistance(data1: [UInt8], data2: [UInt8]) -> Int {
    guard data1.count == data2.count else { return ~0 }
    var distance = 0
    for i in 0 ..< data1.count {
      for o in 0 ..< 8 {
        if (data1[i] >> UInt8(o)) & 1 != (data2[i] >> UInt8(o)) & 1 {
          distance++
        }
      }
    }
    return distance
  }
}
