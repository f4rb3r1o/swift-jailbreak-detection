//
//  TimeStampsGuardian.m
//  JainbrokenDeviceCheck
//
//  Created by macpro on 02/08/2020.
//  Copyright © 2020 johnny. All rights reserved.
//

#import "TimeStampsGuardian.h"

@implementation TimeStampsGuardian

+ (bool) checkForMaliciousTimeStampsModifications
{
    // get cuttent bundle path
    NSString * bundlePath = [[NSBundle mainBundle] bundlePath];
    
    // use string concatenation to get full path of info.plist
    NSString * path = [NSString stringWithFormat: @ "%@ / Info.plist", bundlePath];
    
    // use string concatenation to get full path of executable
    NSString * path2 = [NSString stringWithFormat: @ "%@ / AppName", bundlePath];
    
    NSString * path3 = [[[NSBundle mainBundle] resourcePath] stringByAppendingString:@ "PkgInfo"];
    
    NSFileManager * fileMan = [NSFileManager defaultManager];
    
    // get info.plist modification date
    
    NSDate * modDateInfoPlist = [[fileMan attributesOfItemAtPath:path error:nil] fileModificationDate];

    // get get binary modification date
    
    NSDate * modDateBinaryApp = [[fileMan attributesOfItemAtPath:path2 error:nil] fileModificationDate];

    // get PkgInfo modification date

    NSDate * modDatePkgInfo = [[fileMan attributesOfItemAtPath:path3 error:nil] fileModificationDate];

    if ([modDateInfoPlist timeIntervalSinceReferenceDate] > [modDatePkgInfo timeIntervalSinceReferenceDate]) {
        return YES;
    }
    
    if ([modDateBinaryApp timeIntervalSinceReferenceDate] > [modDatePkgInfo timeIntervalSinceReferenceDate]) {
        return YES;
    }
    return NO;
}

@end
