{
        .name           = "geteip",
        .args_type      = "procname:s?",
        .mhandler.cmd   = do_monitor_proc,
        .params         = "[procname]",
        .help           = "tracking EIP of [procname] as block"
},
