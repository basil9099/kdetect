// SPDX-License-Identifier: GPL-2.0
// kdetect test module: registers a benign ftrace hook so the detector has
// ground truth. It does NOTHING hostile — the hook tail-calls the original.
// Build KDETECT_HIDDEN=1 to also unlink the module (the orphan-hook case);
// removal then requires a reboot, so run only under the VM snapshot discipline.
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kdetect");
MODULE_DESCRIPTION("Benign ftrace-hook ground truth for kdetect phase 3a");

// The function we hook. Harmless: the uname syscall handler.
#define HOOKED_SYMBOL "__x64_sys_newuname"

static struct ftrace_ops kdetect_ops;

// ftrace callback: do nothing but hand control straight back. We deliberately
// do not alter regs->ip, so behaviour is unchanged — the point is only that a
// registered ftrace op becomes visible in enabled_functions.
static void notrace kdetect_callback(unsigned long ip, unsigned long parent_ip,
                                     struct ftrace_ops *op,
                                     struct ftrace_regs *fregs)
{
    // no-op
}

static int __init kdetect_init(void)
{
    int ret;
    unsigned long addr;
    struct kprobe kp = { .symbol_name = HOOKED_SYMBOL };

    // Resolve the address via a throwaway kprobe (the post-5.7 idiom, since
    // kallsyms_lookup_name is no longer exported).
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("kdetect_hooktest: cannot resolve %s (%d)\n", HOOKED_SYMBOL, ret);
        return ret;
    }
    addr = (unsigned long)kp.addr;
    unregister_kprobe(&kp);

    kdetect_ops.func = kdetect_callback;
    kdetect_ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;

    ret = ftrace_set_filter_ip(&kdetect_ops, addr, 0, 0);
    if (ret) {
        pr_err("kdetect_hooktest: set_filter_ip failed (%d)\n", ret);
        return ret;
    }
    ret = register_ftrace_function(&kdetect_ops);
    if (ret) {
        pr_err("kdetect_hooktest: register_ftrace_function failed (%d)\n", ret);
        return ret;
    }
    pr_info("kdetect_hooktest: hooked %s\n", HOOKED_SYMBOL);

#ifdef KDETECT_HIDDEN
    // Unlink from the module list (the Diamorphine-style hide). Removal now
    // needs a reboot; run only under the snapshot discipline.
    list_del(&THIS_MODULE->list);
    pr_info("kdetect_hooktest: hidden from module list\n");
#endif
    return 0;
}

static void __exit kdetect_exit(void)
{
    unregister_ftrace_function(&kdetect_ops);
    pr_info("kdetect_hooktest: unhooked\n");
}

module_init(kdetect_init);
module_exit(kdetect_exit);
