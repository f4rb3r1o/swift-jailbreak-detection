//
//  ContentView.swift
//  Jainbroken Device Check
//
//  Created by macpro on 29/07/2020.
//  Copyright © 2020 johnny. All rights reserved.
//

import SwiftUI

struct JailbreakChecker: View {
    var body: some View {
        ZStack{
            Color.white
            CheckButton(jailbreakChecker: JailbreakScanner())
        }
        .edgesIgnoringSafeArea(.all)
    }
}

struct CheckButton : View{
    //@State var isPressed : Bool = false
    //@State var pressCount : Int = 0
    @State var jailbreakState : Bool = false
    
    let jailbreakChecker : JailbreakScanner?
    
    var body: some View{
        /*VStack{
            Button(action: {
                self.pressCount+=1
                self.isPressed.toggle()
                self.jailbreakState = self.jailbreakChecker.checkJailbreakonDevice()
            })  {
                Text("Tap To Start Scanning")
            }
            if self.isPressed || pressCount > 1*/
        
                //Spacer().frame(minHeight: 50, maxHeight: 200)
                
        VStack
        {
            ForEach(jailbreakChecker!.anomalies){ anomaly in
                AnomalyView(anomaly: anomaly)
            }
            if jailbreakState
            {
                Text("Device Is JailBroken")
            }
            else{
                Text("Device Is Safe")
            }
        }
        .aspectRatio(2/3, contentMode: .fit)
        .edgesIgnoringSafeArea(.all)
        .background(Color.white)
        .foregroundColor(Color.black)
        .font(.title)
        .padding()
    }
}


struct AnomalyView : View{
    var anomaly : AnomalyScanner.Anomaly
    var body: some View{
        ZStack{
            RoundedRectangle(cornerRadius: 15.0).fill(Color.white)
            RoundedRectangle(cornerRadius: 15.0).stroke(lineWidth: 3)
            if anomaly.anomalyState{
                Text("\(anomaly.anomalyName)    ❗️")
            }
            else{
                Text("\(anomaly.anomalyName)    ✅")
            }
        }
        .font(.body)

    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        JailbreakChecker()
    }
}
