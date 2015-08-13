#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "DECAF_callback_common.h"
#include "vmi_callback.h"
#include "utils/Output.h"
#include "DECAF_target.h"
#include <xed-interface.h>

static plugin_interface_t geteip_interface;
static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle blockbegin_handle = DECAF_NULL_HANDLE;
char targetname[512];
uint32_t target_cr3;
static DECAF_Handle check_eip_handle;

static void geteip_block_begin_callback(DECAF_Callback_Params* params)
{
        if(params->bb.env->cr[3] == target_cr3)
        {
                uint32_t eip = cpu_single_env->eip;
                uint32_t eax = cpu_single_env->regs[R_EAX];

                DECAF_printf("EIP = 0x%08x, EAX = 0x%08x\n", eip, eax);
        }
}

static void check_eip(DECAF_Callback_Params* params)
{
        if(params->ec.target_eip_taint)
                printf("CHECK_EIP : SOURCE: 0x%08x TARGET: 0x%08x  TAINT_VALUE: 0x%08x \n", params->ec.source_eip, params->ec.target_eip, params->ec.target_eip_taint);
}

static void geteip_loadmainmodule_callback(VMI_Callback_Params* params)
{
        if(strcmp(params->cp.name,targetname) == 0)
        {
                DECAF_printf("Process %s you spcecified starts \n", params->cp.name);
                target_cr3 = params->cp.cr3;
                blockbegin_handle = DECAF_register_callback(DECAF_BLOCK_BEGIN_CB, &geteip_block_begin_callback, NULL);
        }
}

void do_monitor_proc(Monitor* mon, const QDict* qdict)
{

        if ((qdict != NULL) && (qdict_haskey(qdict, "procname")))
                strncpy(targetname, qdict_get_str(qdict, "procname"), 512);

        targetname[511] = '\0';
        DECAF_printf("Ready to track %s\n", targetname);
}

static int geteip_init(void)
{
        DECAF_printf("Hello, World!\n");

        check_eip_handle = DECAF_register_callback(DECAF_EIP_CHECK_CB, check_eip, NULL);
        DECAF_printf("register eip check callback\n");

        processbegin_handle = VMI_register_callback(VMI_CREATEPROC_CB, &geteip_loadmainmodule_callback, NULL);

        if (processbegin_handle == DECAF_NULL_HANDLE)
                DECAF_printf("Could not register for the create or remove proc events\n");  

        return (0);
}

static void geteip_cleanup(void)
{
        DECAF_printf("Bye, World\n");

        if (processbegin_handle != DECAF_NULL_HANDLE) {
                VMI_unregister_callback(VMI_CREATEPROC_CB, processbegin_handle);  
                processbegin_handle = DECAF_NULL_HANDLE;
        }
        if (blockbegin_handle != DECAF_NULL_HANDLE) {
                DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, blockbegin_handle);
                blockbegin_handle = DECAF_NULL_HANDLE;
        }
}

static mon_cmd_t geteip_term_cmds[] = 
{
#include "plugin_cmds.h"
        {NULL, NULL, },
};

plugin_interface_t* init_plugin(void)
{
        geteip_interface.mon_cmds = geteip_term_cmds;
        geteip_interface.plugin_cleanup = &geteip_cleanup;

        geteip_init();

        return (&geteip_interface);
}
