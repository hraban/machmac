//
//  ViewController.swift
//  SecChecker
//
//  Created by Hraban Luyat on 20/04/2017.
//  Copyright © 2017 Hraban Luyat. All rights reserved.
//

import Cocoa

class ViewController: NSViewController {
    
    private func check(pid: Int, guestPtr: UnsafeMutablePointer<SecCode?>) -> OSStatus {
        let attributes: CFDictionary = [kSecGuestAttributePid as String: pid] as CFDictionary
        // I don't know how to set flags to kSecCSDefaultFlags so I'm just doing it manually
        let flags: SecCSFlags = SecCSFlags.init(rawValue: 0)
        return SecCodeCopyGuestWithAttributes(nil,  attributes, flags, guestPtr)
    }
    
    @IBOutlet weak var resultLabel: NSTextField!
    @IBOutlet weak var pidTextField: NSTextField!
    
    @IBAction func checkBtn(_ sender: AnyObject) {
        if (pidTextField.stringValue != "") {
            let pid = pidTextField.intValue
            let guestPtr = UnsafeMutablePointer<SecCode?>.allocate(capacity: 1)
            resultLabel.intValue = check(pid: Int(pid), guestPtr: guestPtr)
        }
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()

        // Do any additional setup after loading the view.
    }

    override var representedObject: Any? {
        didSet {
        // Update the view, if already loaded.
        }
    }


}

