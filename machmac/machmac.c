//
//  machmac.c
//  machmac
//
//  Created by Hraban Luyat on 17/04/2017.
//  Copyright © 2017 Hraban Luyat. All rights reserved.
//

#include <netinet/in.h>
#include <string.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/vnode.h>

#include <security/mac_policy.h>
#include <mach/mach_types.h>




/************** MAC Policy Handlers **************/

static int is_file_accessible(struct vnode *vp)
{
    const char *vname = NULL;
    char cbuf[MAXCOMLEN+1];
    int retvalue = 0;
    
    if (vp == NULL) // In some cases, absence of information about the node is OK,
    {               // so we allow running the function.
        return (retvalue);
    }
    vname = vnode_getname(vp);
    if(vname) // Node name is not empty
    {
        // and there is an attempt to access
        // the antivirus launch configuration file
        if(strcasecmp(vname, "top_secret_stuff.txt") == 0)
        {
            proc_selfname(cbuf, sizeof(cbuf));
            // while the process attempting to access the file is not
            // an anti-virus update system
            if (strcasecmp(cbuf,"james-bond"))
            {
                retvalue = EPERM; // access should be blocked.
            }
            vnode_putname(vname); // Clearing the node name requested before
        }
    }
    return(retvalue);
}

static int mac_policy_open(
                           kauth_cred_t cred,
                           struct vnode *vp, struct label *label,
                           int acc_mode)
{
    return is_file_accessible(vp);
}

static int mac_policy_unlink(
                             kauth_cred_t cred,
                             struct vnode *dvp,
                             struct label *dlabel,
                             struct vnode *vp,
                             struct label *label,
                             struct componentname *cnp)
{
    return is_file_accessible(vp);
}

static void
mac_policy_initbsd(struct mac_policy_conf *mpc)
{
    // NOP
}


/************ Hook into kext ***************/

// Filling the structure with the pointers to callback functions.
static struct mac_policy_ops mac_ops ={
    .mpo_policy_initbsd  = mac_policy_initbsd,    // Policy initialization
    .mpo_vnode_check_open = mac_policy_open,      // Policy initialization
    .mpo_vnode_check_unlink = mac_policy_unlink,  // File deletion handler
};

// Filling the structure with information on our policy
static struct mac_policy_conf mac_policy_conf =
{
    .mpc_name         = "protect_demo",
    .mpc_fullname       = "Protect demo!",
    .mpc_labelnames     = NULL,
    .mpc_labelname_count  = 0,
    .mpc_ops        = &mac_ops,
    .mpc_loadtime_flags   = MPC_LOADTIME_FLAG_UNLOADOK, // The policy is UNLOADABLE!
    .mpc_field_off      = NULL,
    .mpc_runtime_flags    = 0
};

// The pointer to the registered policy
// Necessary for deregistering the policy
static mac_policy_handle_t mac_handle;  // Driver entry point


kern_return_t machmac_start(kmod_info_t * ki, void *d)
{
    // In case of successful execution of mac_policy_register function
    // the pointer to the registered policy
    // will be written to the mac_handle variable
    // Registering the policy
    return mac_policy_register(&mac_policy_conf, &mac_handle, d);}

kern_return_t machmac_stop(kmod_info_t *ki, void *d)
{
  return mac_policy_unregister(mac_handle); // Deregistering the policy
}
