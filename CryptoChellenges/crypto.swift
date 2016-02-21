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
  
  static func decipherSingleByteXor(string: [UInt8], key: UInt8) -> [UInt8] {
    return string.map { $0 ^ key }
  }
  
  static func cipherStringWithKey(string: String, key: [UInt8]) -> String {
    return string.bytes.enumerate().map({ (index: Int, byte: UInt8) in
      return byte ^ key[index % key.count]
    }).hexStringRepresentation
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
