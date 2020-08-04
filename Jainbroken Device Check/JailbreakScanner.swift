//
//  JailbreakScanner.swift
//  Jainbroken Device Check
//
//  Created by macpro on 30/07/2020.
//  Copyright © 2020 johnny. All rights reserved.
//

import Foundation
import SwiftUI

class JailbreakScanner {
    
    private var anomalyScanner = AnomalyScanner()
    
    func checkJailbreakonDevice() -> Bool {
        anomalyScanner.dispatchAllScanMethods()
    }
    
    var anomalies: Array<AnomalyScanner.Anomaly>
    {
        anomalyScanner.anomalies
    }
}
