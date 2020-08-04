//
//  DebuggerDefeater.h
//  JainbrokenDeviceCheck
//
//  Created by macpro on 02/08/2020.
//  Copyright © 2020 johnny. All rights reserved.
//

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/stat.h>
#import <mach-o/dyld.h>
#include <string.h>
#include <mach/mach.h>

#include <errno.h>



bool debugger_sysctl(void);

bool check_symbolic_links(void);

bool dyld_check(void);

bool check_app_running_root(void);

bool check_signiture_validity(void);

bool check_root_task_port_abuse(void);

bool abuse_validation(mach_port_name_t kernel_task);

bool try_hgsp(mach_port_name_t kernel_task);

//bool try_pst2(void);

