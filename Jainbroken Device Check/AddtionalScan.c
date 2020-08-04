//
//  DebuggerDefeater.c
//  JainbrokenDeviceCheck
//
//  Created by macpro on 02/08/2020.
//  Copyright © 2020 johnny. All rights reserved.
//

#include "AdditionalScans.h"


bool debugger_sysctl(void)
// Returns true if the current process is being debugged (either
// running under the debugger or has a debugger attached post facto).
{
    int mib[4];
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    
    // Initialize the flags so that, if sysctl fails for some bizarre
    // reason, we get a predictable result.
    
    info.kp_proc.p_flag = 0;
    
    // Initialize mib, which tells sysctl the info we want, in this case
    // we're looking for information about a specific process ID.
    
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    
    // Call sysctl.
    
    if (sysctl(mib, 4, &info, &info_size, NULL, 0) == -1)
    {
        return false;
    }
    
    // We're being debugged if the P_TRACED flag is set.
    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}

bool check_symbolic_links()
{
    struct stat s;
    if(lstat("/Applications", &s) || lstat("/var/stash/Library/Ringtones", &s) || lstat("/var/stash/Library/Wallpaper", &s)
       || lstat("/var/stash/usr/include", &s) || lstat("/var/stash/usr/libexec", &s)  || lstat("/var/stash/usr/share", &s) || lstat("/var/stash/usr/arm-apple-darwin9", &s))
    {
        if(s.st_mode & S_IFLNK){
            return true;
        }
    }
    return false;
}

bool dyld_check()
{
    //Get count of all currently loaded DYLD
    uint32_t count = _dyld_image_count();
    for(uint32_t i = 0; i < count; i++)
    {
        //Name of image (includes full path)
        const char *dyld = _dyld_get_image_name(i);
        if(!strstr(dyld, "MobileSubstrate")) {
            continue;
        }
        else {
            return true;
        }
    }
    return false;
}

bool check_app_running_root(void)
{
    return getuid() <= 10; // checks that the application process ID is not among the system process IDs (less than or equal to 10)
}

bool check_root_task_port_abuse(void) {
    
    mach_port_name_t kernel_task;
    
    // asking send rights to the kernel's task port - check for tfp0
    
    task_for_pid(mach_task_self(), 0, &kernel_task);

    if (kernel_task == MACH_PORT_NULL) {
        return false;
    }
    
    if(abuse_validation(kernel_task))
    {
        return true;
    }
    
    if(try_hgsp(kernel_task))
    {
        return true;
    }
    
    return false;
}

/*
bool try_pst2()
{
    
    bool success = false;
    
    mach_port_t host = mach_host_self();
    
    if (host == MACH_PORT_NULL)
    {
        return success;
    }
   
    // Return the default processor set.
    
    processor_set_name_t pset_name;
    kern_return_t kr = processor_set_default(host, &pset_name);
    
    if (kr != KERN_SUCCESS)
    {
        mach_port_deallocate(mach_task_self(), host);
    }
    
    // Translate a processor set name port into a processor set control port.
    
    processor_set_t pset;
    
    kr = host_processor_set_priv(host, pset_name, &pset);
    
    if (kr != KERN_SUCCESS)
    {
        mach_port_deallocate(mach_task_self(), pset_name);
    }
    
    task_array_t tasks;
    mach_msg_type_number_t task_count;
    
    // Return a list of pointers to all tasks currently assigned to the target processor set.
    
    kr = processor_set_tasks(pset, &tasks, &task_count);
    
    if (kr != KERN_SUCCESS)
    {
        mach_port_deallocate(mach_task_self(), pset);
    }
    
    for (size_t i = 1; i < task_count; i++)
    {
        mach_port_deallocate(mach_task_self(), tasks[i]);
    }
    
    mach_port_name_t kernel_task = tasks[0];
    
    success = abuse_validation(kernel_task);
    
    vm_deallocate(mach_task_self(), (vm_address_t)tasks, task_count * sizeof(*tasks));
    
    return success;
}
*/

bool try_hgsp(mach_port_name_t kernel_task) {
    
    mach_port_t host = mach_host_self();
    if (host == MACH_PORT_NULL) {
        return false;
    }
    
    for (int port_id = 0; port_id <= HOST_MAX_SPECIAL_PORT; port_id++) {
        host_get_special_port(host, 0, port_id, &kernel_task);
        if (abuse_validation(kernel_task)) {
            break;
        }
    }
    
    mach_port_deallocate(mach_task_self(), host);
    
    return (kernel_task != MACH_PORT_NULL);
}

 
bool abuse_validation(mach_port_name_t kernel_task)
{
    pid_t pid;
    
    // getting the pid associated with this port
    // check if the kernel's task port has successfully retrieved
    kern_return_t kr = pid_for_task(kernel_task, &pid);
    
    if (kr != KERN_SUCCESS || pid != 0) {
        mach_port_deallocate(mach_task_self(), kernel_task);
        kernel_task = MACH_PORT_NULL;
        return false;
    }
    
    return true;
}
