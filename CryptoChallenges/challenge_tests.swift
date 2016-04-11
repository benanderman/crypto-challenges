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
    testBase64()
    testHammingDistance()
    testChallenge1()
    testChallenge2()
    testChallenge3()
    testChallenge4()
    testChallenge5()
    testChallenge6()
    testEuler59()
    testChallenge7()
    testChallenge8()
    testChallenge9()
    testChallenge10()
    testChallenge11()
    testChallenge12()
    testChallenge13()
    testChallenge14()
    testChallenge15()
    testChallenge16()
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
	
  func testEuler59() {
    let input = [UInt8](arrayLiteral: 79,59,12,2,79,35,8,28,20,2,3,68,8,9,68,45,0,12,9,67,68,4,7,5,23,27,1,21,79,85,78,79,85,71,38,10,71,27,12,2,79,6,2,8,13,9,1,13,9,8,68,19,7,1,71,56,11,21,11,68,6,3,22,2,14,0,30,79,1,31,6,23,19,10,0,73,79,44,2,79,19,6,28,68,16,6,16,15,79,35,8,11,72,71,14,10,3,79,12,2,79,19,6,28,68,32,0,0,73,79,86,71,39,1,71,24,5,20,79,13,9,79,16,15,10,68,5,10,3,14,1,10,14,1,3,71,24,13,19,7,68,32,0,0,73,79,87,71,39,1,71,12,22,2,14,16,2,11,68,2,25,1,21,22,16,15,6,10,0,79,16,15,10,22,2,79,13,20,65,68,41,0,16,15,6,10,0,79,1,31,6,23,19,28,68,19,7,5,19,79,12,2,79,0,14,11,10,64,27,68,10,14,15,2,65,68,83,79,40,14,9,1,71,6,16,20,10,8,1,79,19,6,28,68,14,1,68,15,6,9,75,79,5,9,11,68,19,7,13,20,79,8,14,9,1,71,8,13,17,10,23,71,3,13,0,7,16,71,27,11,71,10,18,2,29,29,8,1,1,73,79,81,71,59,12,2,79,8,14,8,12,19,79,23,15,6,10,2,28,68,19,7,22,8,26,3,15,79,16,15,10,68,3,14,22,12,1,1,20,28,72,71,14,10,3,79,16,15,10,68,3,14,22,12,1,1,20,28,68,4,14,10,71,1,1,17,10,22,71,10,28,19,6,10,0,26,13,20,7,68,14,27,74,71,89,68,32,0,0,71,28,1,9,27,68,45,0,12,9,79,16,15,10,68,37,14,20,19,6,23,19,79,83,71,27,11,71,27,1,11,3,68,2,25,1,21,22,11,9,10,68,6,13,11,18,27,68,19,7,1,71,3,13,0,7,16,71,28,11,71,27,12,6,27,68,2,25,1,21,22,11,9,10,68,10,6,3,15,27,68,5,10,8,14,10,18,2,79,6,2,12,5,18,28,1,71,0,2,71,7,13,20,79,16,2,28,16,14,2,11,9,22,74,71,87,68,45,0,12,9,79,12,14,2,23,2,3,2,71,24,5,20,79,10,8,27,68,19,7,1,71,3,13,0,7,16,92,79,12,2,79,19,6,28,68,8,1,8,30,79,5,71,24,13,19,1,1,20,28,68,19,0,68,19,7,1,71,3,13,0,7,16,73,79,93,71,59,12,2,79,11,9,10,68,16,7,11,71,6,23,71,27,12,2,79,16,21,26,1,71,3,13,0,7,16,75,79,19,15,0,68,0,6,18,2,28,68,11,6,3,15,27,68,19,0,68,2,25,1,21,22,11,9,10,72,71,24,5,20,79,3,8,6,10,0,79,16,8,79,7,8,2,1,71,6,10,19,0,68,19,7,1,71,24,11,21,3,0,73,79,85,87,79,38,18,27,68,6,3,16,15,0,17,0,7,68,19,7,1,71,24,11,21,3,0,71,24,5,20,79,9,6,11,1,71,27,12,21,0,17,0,7,68,15,6,9,75,79,16,15,10,68,16,0,22,11,11,68,3,6,0,9,72,16,71,29,1,4,0,3,9,6,30,2,79,12,14,2,68,16,7,1,9,79,12,2,79,7,6,2,1,73,79,85,86,79,33,17,10,10,71,6,10,71,7,13,20,79,11,16,1,68,11,14,10,3,79,5,9,11,68,6,2,11,9,8,68,15,6,23,71,0,19,9,79,20,2,0,20,11,10,72,71,7,1,71,24,5,20,79,10,8,27,68,6,12,7,2,31,16,2,11,74,71,94,86,71,45,17,19,79,16,8,79,5,11,3,68,16,7,11,71,13,1,11,6,1,17,10,0,71,7,13,10,79,5,9,11,68,6,12,7,2,31,16,2,11,68,15,6,9,75,79,12,2,79,3,6,25,1,71,27,12,2,79,22,14,8,12,19,79,16,8,79,6,2,12,11,10,10,68,4,7,13,11,11,22,2,1,68,8,9,68,32,0,0,73,79,85,84,79,48,15,10,29,71,14,22,2,79,22,2,13,11,21,1,69,71,59,12,14,28,68,14,28,68,9,0,16,71,14,68,23,7,29,20,6,7,6,3,68,5,6,22,19,7,68,21,10,23,18,3,16,14,1,3,71,9,22,8,2,68,15,26,9,6,1,68,23,14,23,20,6,11,9,79,11,21,79,20,11,14,10,75,79,16,15,6,23,71,29,1,5,6,22,19,7,68,4,0,9,2,28,68,1,29,11,10,79,35,8,11,74,86,91,68,52,0,68,19,7,1,71,56,11,21,11,68,5,10,7,6,2,1,71,7,17,10,14,10,71,14,10,3,79,8,14,25,1,3,79,12,2,29,1,71,0,10,71,10,5,21,27,12,71,14,9,8,1,3,71,26,23,73,79,44,2,79,19,6,28,68,1,26,8,11,79,11,1,79,17,9,9,5,14,3,13,9,8,68,11,0,18,2,79,5,9,11,68,1,14,13,19,7,2,18,3,10,2,28,23,73,79,37,9,11,68,16,10,68,15,14,18,2,79,23,2,10,10,71,7,13,20,79,3,11,0,22,30,67,68,19,7,1,71,8,8,8,29,29,71,0,2,71,27,12,2,79,11,9,3,29,71,60,11,9,79,11,1,79,16,15,10,68,33,14,16,15,10,22,73).base64Representation
    if let result = Crypto.decipherRepeatingKeyXorBase64(input, keySize: 3) {
      var sum = 0
      for value in result.result.bytes {
        sum += Int(value)
      }
      print("decipherRepeatingKeyXorBase64 (with 6.txt):\nKey: \(result.key.stringRepresentation)\n\(result.result)\n\(sum)\n")
    } else {
      print("Failed to decipher")
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
    
    func profileFor(email: String) -> String {
      let trimmed = email.stringByTrimmingCharactersInSet(NSCharacterSet(charactersInString: "&="))
      return Crypto.encryptAES128ECB(UFESerializeUser(trimmed, uid: "10", role: "user").bytes, key: key).hexStringRepresentation
    }
    
    var justAdmin = profileFor("1234567890" + Crypto.padUsingPKCS7("admin".bytes, multiple: 16).stringRepresentation)
    justAdmin = justAdmin.substringWithRange(justAdmin.startIndex.advancedBy(32) ..< justAdmin.startIndex.advancedBy(64))
    
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
    
    guard let adminProfileBytes = adminProfile.bytesFromHex, let decrypted = Crypto.decryptAES128ECB(adminProfileBytes, key: key) else {
      print("Failed to decrypt admin profile 😞\n")
      return
    }
    guard let unpaddedString = Crypto.stripPKCS7Padding(decrypted)?.stringRepresentation else {
      print("Failed to unpad/stringify admin profile\n")
      return
    }
    
    print("Admin profile: \(parseUFEString(unpaddedString))\n")
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
  
  func testChallenge15() {
    let good1 = Crypto.padUsingPKCS7("1234567890".bytes)
    let good2 = Crypto.padUsingPKCS7("1234567890123456".bytes)
    let bad = "123456789012345".bytes + [5]
    
    print("Strip padding of \(good1) = \(Crypto.stripPKCS7Padding(good1))")
    print("Strip padding of \(good2) = \(Crypto.stripPKCS7Padding(good2))")
    print("Strip padding of \(bad) = \(Crypto.stripPKCS7Padding(bad))\n")
  }
  
  func testChallenge16() {
    let key = Crypto.randomBytes(16)
    let iv = Crypto.randomBytes(16)
    
    func encrypt(input: [UInt8]) -> [UInt8] {
      let amended = "comment1=cooking%20MCs;userdata=".bytes + input + ";comment2=%20like%20a%20pound%20of%20bacon".bytes
      return Crypto.encryptAES128CBC(amended, key: key, iv: iv)
    }
    
    func checkForAdmin(input: [UInt8]) -> Bool {
      guard let decrypted = Crypto.decryptAES128CBC(input, key: key, iv: iv) else { return false }
      let admin = ";admin=true;".bytes
      for i in 0 ..< decrypted.count - admin.count {
        if decrypted[i ..< i + admin.count] == admin[0 ..< admin.count] {
          return true
        }
      }
      return false
    }
    
    let input = "12345".bytes + [UInt8](count: 11, repeatedValue: 0)
    let xor = [UInt8](count: 5, repeatedValue: 0) + ";admin=true".bytes
    var result = encrypt(input)
    result[16 * 1 ..< 16 * 2] = Crypto.xorData([UInt8](result[16 * 1 ..< 16 * 2]), data2: xor)![0 ..< 16]
    
    print("Found ;admin=true; in result: \(checkForAdmin(result))\n")
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