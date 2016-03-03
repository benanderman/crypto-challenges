//
//  challenge_tests.swift
//  CryptoChellenges
//
//  Created by Ben Anderman on 2/16/16.
//  Copyright © 2016 Ben Anderman. All rights reserved.
//

import Foundation

func testChallenges() {
  
  func testAllChallenges() {
//    testBase64()
//    testHammingDistance()
//    testChallenge1()
//    testChallenge2()
//    testChallenge3()
//    testChallenge4()
//    testChallenge5()
//    testChallenge6()
//    testChallenge7()
//    testChallenge8()
//    testChallenge9()
//    testChallenge10()
//    testChallenge11()
    testChallenge12()
    testChallenge13()
    testChallenge14()
  }
  
  testAllChallenges()
  
  func testChallenge1() {
    let base64TestInput = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    if let result = Crypto.hexToBase64(base64TestInput) {
      print("\(base64TestInput)\nhexToBase64:\n\(result)\n")
    } else {
      print("Failed to convert\n")
    }
  }
  
  func testChallenge2() {
    let xorTestInput1 = "1c0111001f010100061a024b53535009181c"
    let xorTestInput2 = "686974207468652062756c6c277320657965"
    if let output = Crypto.xorHexStrings(xorTestInput1, hex2: xorTestInput2) {
      print("\(xorTestInput1), \(xorTestInput2)\nxorHexStrings:\n\(output)\n")
    } else {
      print("Failed to xor\n")
    }
  }
  
  func testChallenge3() {
    let singleByteXorInput = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    if let output3 = Crypto.decipherSingleByteXorHex([singleByteXorInput]) {
      print(singleByteXorInput + "\ndecipherSingleByteXorHex:\n" + output3 + "\n")
    } else {
      print("Failed to decipher\n")
    }
  }
  
  func testChallenge4() {
    do {
      let singleByteXor2Input = try NSString(contentsOfFile: "4.txt", encoding: NSUTF8StringEncoding)
      let lines = singleByteXor2Input.componentsSeparatedByString("\r\n")
      if let result = Crypto.decipherSingleByteXorHex(lines) {
        print("decipherSingleByteXorHex (with 4.txt):\n\(result)\n")
      } else {
        print("Failed to decipher\n")
      }
    } catch {
      print("Failed to read input file\n")
    }
  }
  
  func testChallenge5() {
    let repeatingByteCipherInput = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    let result = Crypto.cipherStringWithKey(repeatingByteCipherInput, key: "ICE".bytes)
    print("\(repeatingByteCipherInput)\ncipherStringWithKey('ICE'):\n\(result)\n")
  }
  
  func testChallenge6() {
    do {
      var repeatingByteDecipherInput = try NSString(contentsOfFile: "6.txt", encoding: NSUTF8StringEncoding)
      repeatingByteDecipherInput = repeatingByteDecipherInput.stringByReplacingOccurrencesOfString("\r\n", withString: "")
      if let result = Crypto.decipherRepeatingKeyXorBase64(String(repeatingByteDecipherInput)) {
        print("decipherRepeatingKeyXorBase64 (with 6.txt):\nKey: \(result.key.stringRepresentation)\n\(result.result)\n")
      } else {
        print("Failed to decipher")
      }
    } catch {
      print("Failed to read input file\n")
    }
  }
  
  func testChallenge7() {
    guard let aes128Input = getFileWithoutNewLines("7.txt")?.bytesFromBase64 else {
      print("Failed to read input file\n")
      return
    }
    let key = "YELLOW SUBMARINE"
    if let result = Crypto.decryptAES128ECB(aes128Input, key: key.bytes) {
      print("decodeAES128Base64 (with 7.txt):\n\(result.stringRepresentation)\n")
    } else {
      print("Failed to decode AES128")
    }
  }
  
  func testChallenge8() {
    do {
      let input = try NSString(contentsOfFile: "8.txt", encoding: NSUTF8StringEncoding)
      let lines = input.componentsSeparatedByString("\r\n")
      if let result = Crypto.detectAES128Hex(lines) {
        print("detectAES128Base64 (with 8.txt):\n\(result)\n")
      } else {
        print("Failed to decipher\n")
      }
    } catch {
      print("Failed to read input file\n")
    }
  }
  
  func testHammingDistance() {
    let hammingInput1 = "this is a test"
    let hammingInput2 = "wokka wokka!!!"
    let resultInt = Crypto.hammingDistance(hammingInput1.bytes, data2: hammingInput2.bytes)
    // Should be 37
    print("editDistance('\(hammingInput1)', '\(hammingInput2)') = \(resultInt)\n")
  }
  
  func testChallenge9() {
    let input = "YELLOW SUBMARINE".bytes
    let result = Crypto.padUsingPKCS7(input, multiple: 20)
    print("padUsingPKCS7(\(input), multiple: 20) = \(result)\n")
  }
  
  func testChallenge10() {
    let iv = Crypto.randomBytes(16)
    let input = "These are not rap lyrics."
    let key = "YELLOW SUBMARINE"
    let result = Crypto.encryptAES128CBC(input.bytes, key: key.bytes, iv: iv)
    print("encryptAES128CBC(\(input), key: \(key), iv: \(iv)) = \(result.base64Representation)\n")
    
    if let result2 = Crypto.decryptAES128CBC(result, key: key.bytes, iv: iv) {
      print("decryptAES128CBC(...) = \(result2.stringRepresentation)\n")
    } else {
      print("Failed to decrypt AES128 CBC\n")
    }
    
    if let input2 = getFileWithoutNewLines("10.txt")?.bytesFromBase64 {
      let zeroIV = [UInt8](count: 16, repeatedValue: 0)
      if let result3 = Crypto.decryptAES128CBC(input2, key: key.bytes, iv: zeroIV) {
        print("decryptAES128CBC (with 10.txt):\n\(result3.stringRepresentation)\n")
      } else {
        print("Failed to decrypt\n")
      }
    } else {
      print("Failed to read input file\n")
    }
  }
  
  func testChallenge11() {
    let input = [UInt8](count: 48, repeatedValue: 65)
    for _ in 0 ..< 10 {
      let result = Crypto.encryptAES128Random(input)
      let usedECBGuess = Crypto.detectAES128Hex([result.result.hexStringRepresentation]) != nil
      let guessedCorrectly = usedECBGuess != result.usedCBC
      print("Guessed encryption type correctly: \(guessedCorrectly) (\(result.usedCBC ? "CBC" : "ECB"))")
    }
    print("\n")
  }
  
  func decryptECBWithEncryptor(encryptor: ([UInt8]) -> [UInt8]) -> (blockSize: Int, usingECB: Bool, decoded: [UInt8]) {
    var blockSize = 0
    var previousResult = [UInt8]()
    for i in 1...129 {
      let result = encryptor([UInt8](count: i, repeatedValue: 65))
      if i > 1 && previousResult[0 ..< i - 1] == result[0 ..< i - 1] {
        blockSize = i - 1;
        break
      }
      previousResult = result
    }
    
    let input = [UInt8](count: 48, repeatedValue: 65)
    let result = encryptor(input)
    let usedECBGuess = Crypto.detectAES128Hex([result.hexStringRepresentation]) != nil
    
    let length = result.count - input.count
    var decoded = [UInt8]()
    var decodedBlock = [UInt8](count: 16, repeatedValue: 65)
    for i in 0 ..< length {
      let o = i / blockSize * blockSize
      let injectSize = blockSize - (i % blockSize + 1)
      let inject = [UInt8](decodedBlock[0 ..< injectSize])
      let result = [UInt8](encryptor(inject)[o ..< o + blockSize])
      for c in 0 ..< UInt8.max {
        let test = [UInt8](encryptor(decodedBlock[1 ..< blockSize] + [c])[0 ..< blockSize])
        if (test == result) {
          decoded.append(c)
          decodedBlock.append(c)
          decodedBlock.removeFirst()
          break;
        }
      }
    }
    
    return (blockSize, usedECBGuess, decoded)
  }
  
  func testChallenge12() {
    let (blockSize, usedECB, decrypted) = decryptECBWithEncryptor(Crypto.encryptAES128RandomStaticECB)
    
    print("Block size is: \(blockSize)")
    print("Using ECB: \(usedECB ? "yes" : "no")")
    print("The decoded text is:\n\(decrypted.stringRepresentation)\n")
  }
  
  func testChallenge13() {
    let key = Crypto.randomBytes(16)
    
    func UFESerializeUser(email: String, uid: String, role: String) -> String {
      return "email=\(email)&uid=\(uid)&role=\(role)"
    }
    
    func parseUFEString(input: String) -> [String:String] {
      var result = [String:String]()
      for pair in input.componentsSeparatedByString("&") {
        var splitPair = pair.componentsSeparatedByString("=")
        guard splitPair.count == 2 else { fatalError() }
        result[splitPair[0]] = splitPair[1]
      }
      return result
    }
    
    func profileFor(var email: String) -> String {
      email = email.stringByTrimmingCharactersInSet(NSCharacterSet(charactersInString: "&="))
      return Crypto.encryptAES128ECB(UFESerializeUser(email, uid: "10", role: "user").bytes, key: key).hexStringRepresentation
    }
    
    var justAdmin = profileFor("1234567890" + Crypto.padUsingPKCS7("admin".bytes, multiple: 16).stringRepresentation)
    justAdmin = justAdmin.substringWithRange(Range(start: justAdmin.startIndex.advancedBy(32), end: justAdmin.startIndex.advancedBy(64)))
    
    var adminProfile = ""
    var email = "a@gmail.com"
    var lastResult = profileFor(email)
    for _ in 0 ..< 16 {
      email = "a" + email
      var result = profileFor(email)
      // If this resulted in a new block being created (which would be a block of all padding)
      if result.utf8.count > lastResult.utf8.count {
        // Push "user" into the new block
        result = profileFor("user" + email)
        adminProfile = result.substringToIndex(result.startIndex.advancedBy(result.utf8.count - 32)) + justAdmin
        break
      } else {
        lastResult = result
      }
    }
    
    if let adminProfileBytes = adminProfile.bytesFromHex, let decrypted = Crypto.decryptAES128ECB(adminProfileBytes, key: key)?.stringRepresentation {
      print("Admin profile: \(parseUFEString(decrypted))\n")
    } else {
      print("Failed to decrypt admin profile 😞\n")
    }
  }
  
  func testChallenge14() {
    
    let a = Crypto.randomBytes(16).map { $0 == 1 ? 2 : $0 }
    let b = [UInt8](count: 16, repeatedValue: 1)
    let insert = a + b + b + a
    
    func encryptAndRemovePrefix(input: [UInt8]) -> [UInt8] {
      var result = [UInt8]()
      mainLoop: for _ in 0 ... 10000 {
        result = Crypto.encryptAES128RandomStaticECBNoise(insert + input)
        for i in 3 ..< result.count / 16 {
          let blocks = (i - 3 ... i).map { result[$0 * 16 ..< ($0 + 1) * 16] }
          if blocks[0] == blocks[3] && blocks[1] == blocks[2] && blocks[0] != blocks[1] {
            result = [UInt8](result[(i + 1) * 16 ..< result.count])
            break mainLoop
          }
        }
      }
      return result
    }
    
    let (blockSize, usedECB, decrypted) = decryptECBWithEncryptor(encryptAndRemovePrefix)
    
    print("Block size is: \(blockSize)")
    print("Using ECB: \(usedECB ? "yes" : "no")")
    print("The decoded text is:\n\(decrypted.stringRepresentation)\n")
  }
  
  func testBase64() {
    let inputs = ["1234", "12345", "123456"]
    for input in inputs {
      if let result = input.bytes.base64Representation.bytesFromBase64?.stringRepresentation {
        print("\(input) round trip base64 = \(result)\n")
      } else {
        print("Failed to convert \(input) to base64 and back\n")
      }
    }
  }
  
  func getFileWithoutNewLines(path: String) -> String? {
    do {
      let content = try NSString(contentsOfFile: path, encoding: NSUTF8StringEncoding)
      return content.stringByReplacingOccurrencesOfString("\r\n", withString: "")
    } catch {
      return nil
    }
  }
}