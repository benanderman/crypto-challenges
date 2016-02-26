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
    testChallenge7()
    testChallenge8()
    testChallenge9()
    testChallenge10()
    testChallenge11()
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
    if let result = Crypto.decryptAES128(aes128Input, key: key.bytes) {
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