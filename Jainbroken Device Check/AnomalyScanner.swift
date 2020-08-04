//
//  AnomalyScanner.swift
//  Jainbroken Device Check
//
//  Created by macpro on 30/07/2020.
//  Copyright © 2020 johnny. All rights reserved.
//

/*
    1. Check for cydia app :
    /Applications/Cydia.app

    2. Check for Mobile Substrate:
    /Library/MobileSubstrate/MobileSubstrate.dylib

    3. Check for ssh deamon existence:
    /bin/bash

    4. Check for bash existence:
    /bin/bash

    5. Check for sandboxing validity (an app is constrained to only be able to perform I/O operations within the app’s budle),
    We can try to write some file outside of it:

    6. /private/jailbreak.txt

    7. Check for successful call to the Cydia URL scheme:
    cydia://package/com.example.package

*/

import Foundation
import UIKit
import Darwin

class Constants{
    
    /*static let anomaliesNames: Set<String> = ["Cydia App Exists", "Mobile Substrate Installed", "ssh Deamon Exists", "/bin/bash File Exist", "Sandbox Constraint", "Cydia URL Scheme", "Forbidden API Check", "Debugger Present Check", ".dyld Check"]
    */
    static let checkCydiaApp :()->Bool = { return canOpen(path: "/Applications/Cydia.app") }
    
    static let checkMobileSubstrate:()->Bool = { return canOpen(path: "/Library/MobileSubstrate/MobileSubstrate.dylib") }
    
    static let checkSshDeamon:()->Bool = { return (canOpen(path: "/usr/sbin/sshd") || canOpen(path: "/usr/bin/ssh")) }
    
    static let checkApt:()->Bool = { return (canOpen(path: "/etc/apt") || canOpen(path: "/private/var/lib/apt"))}
    
    static let checkBinBash :()->Bool = { return canOpen(path: "/bin/bash") }
    
    static let checkSandboxConstraint : ()-> Bool =
    {
        
        let fileManager = FileManager.default
        
        let path = "/private/jailbreak.txt"
        
        do
        {
            try "anyString".write(toFile: path, atomically: true, encoding: String.Encoding.utf8)
            try fileManager.removeItem(atPath: path)
            }catch {
            return false
        }
        
        
        return false
    }
    
    
    static let checkCydiaUrlScheme :()->Bool =
    {
         if let url = URL(string: "cydia://package/com.example.package")
         {
                if UIApplication.shared.canOpenURL(url) {
                   return true
                }
        }
        return false
    }

    static func apiCheck() -> Bool
    {
        var pid: pid_t = -1

        var status: Int32 = 0
        posix_spawn(&pid, "", nil, nil, [], nil);
        waitpid(pid, &status, WEXITED);
        
        if pid >= 0
        {
            return true
        }
        return false
    }

    static func dyldCheck() -> Bool
    {
        return dyld_check()
    }
    
    static func isDeubggerPresent() -> Bool
    {
        return (debugger_sysctl() || getppid() != 1) // launchd pid = 1
    }
    
    static func checkSymbolicLinks() -> Bool
    {
        return check_symbolic_links()
    }
    
    static func checkAppRooted() -> Bool
    {
        return check_app_running_root()
    }
    
    static func checkModificationDates() -> Bool
    {
        return TimeStampsGuardian.checkForMaliciousTimeStampsModifications()
    }
    
    static func checkForTaskPortAbuse() -> Bool
    {
        return check_root_task_port_abuse()
    }
    
    static func canOpen(path: String) -> Bool
    {
        let file = fopen(path, "r")
        guard file != nil else { return false } // guard - same as if let
        fclose(file)
        return true
    }
    
    static func isSimulator() -> Bool
    {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }
    
    static let scanners : Dictionary<String,()->Bool> = ["Check Cydia App":checkCydiaApp, "Mobile Substrate Installed":checkMobileSubstrate, "Check For ssh Deamon":checkSshDeamon, "Check For /bin/bash":checkBinBash, "Sandbox Contraint":checkSandboxConstraint, "Cydia Url Scheme":checkCydiaUrlScheme, "Forbidden API Check":apiCheck, "Is Debugger Present Check":isDeubggerPresent, "Dyld Check":dyldCheck, "Symbolic Links Check": checkSymbolicLinks, "App Running As Root Check":checkAppRooted, "Timestamps Modification Check": checkModificationDates, "root Task Port Abuse Check": checkForTaskPortAbuse]
}

struct AnomalyScanner {
    private(set) var anomalies: [Anomaly] = [Anomaly]()
    
    init() {
        if Constants.isSimulator()
        {
            #if DEBUG
            // nothing here ...
            #else
            exit(0)
            #endif
        }
        var i = 0
        for methodName in Constants.scanners
        {
            self.anomalies.append(Anomaly(id: i, anomalyName: methodName.key, anomalyState: false))
            i+=1
        }

    }
    
    mutating func dispatchAllScanMethods() -> Bool {
        var retVal : Bool = false
        
        var anomalyIndex : Int = 0
        for anomaly in anomalies
        {
            if Constants.scanners[anomaly.anomalyName]!()
            {
                anomalies[anomalyIndex].anomalyState = true
                if !retVal
                {
                    retVal = true
                }
            }
            anomalyIndex+=1
        }
        // at this phase, all anomalies will have their state set
        return retVal
    }
    
    struct Anomaly: Identifiable {
        var id: Int
        let anomalyName: String
        var anomalyState: Bool
    }
}
