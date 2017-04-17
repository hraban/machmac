//
//  machmac.c
//  machmac
//
//  Created by Hraban Luyat on 17/04/2017.
//  Copyright © 2017 Hraban Luyat. All rights reserved.
//

#include <mach/mach_types.h>

kern_return_t machmac_start(kmod_info_t * ki, void *d);
kern_return_t machmac_stop(kmod_info_t *ki, void *d);

kern_return_t machmac_start(kmod_info_t * ki, void *d)
{
    return KERN_SUCCESS;
}

kern_return_t machmac_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
