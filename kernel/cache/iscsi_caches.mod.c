#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xa0c1c7e8, "module_layout" },
	{ 0x5457a9aa, "kmem_cache_destroy" },
	{ 0x3554d5f7, "iet_mem_size" },
	{ 0x9bb274b4, "mem_map" },
	{ 0x76ebea8, "pv_lock_ops" },
	{ 0xf17a530b, "page_address" },
	{ 0xe0895973, "__lock_page" },
	{ 0xe8b63ace, "radix_tree_range_tag_if_tagged" },
	{ 0x6acc2418, "iet_mem_virt" },
	{ 0xe1819f15, "mutex_unlock" },
	{ 0x1f00ebee, "kthread_create_on_node" },
	{ 0x9b823f21, "mutex_trylock" },
	{ 0xb2d3cb20, "current_task" },
	{ 0x5e651052, "__mutex_init" },
	{ 0x50eedeb8, "printk" },
	{ 0xebf15e2e, "kthread_stop" },
	{ 0xa1c76e0a, "_cond_resched" },
	{ 0xb4390f9a, "mcount" },
	{ 0xe8d8df47, "kmem_cache_free" },
	{ 0x16305289, "warn_slowpath_null" },
	{ 0x98bf94b0, "mutex_lock" },
	{ 0xcde172ac, "radix_tree_gang_lookup_tag_slot" },
	{ 0x62f623a9, "unlock_page" },
	{ 0x5d5b5a16, "radix_tree_delete" },
	{ 0x4646dc37, "kmem_cache_alloc" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0x54434d6, "radix_tree_tag_set" },
	{ 0x47b3f862, "radix_tree_lookup_slot" },
	{ 0xd62c833f, "schedule_timeout" },
	{ 0xf1faac3a, "_raw_spin_lock_irq" },
	{ 0x4c6de143, "wake_up_process" },
	{ 0x67f7403e, "_raw_spin_lock" },
	{ 0x5642793a, "radix_tree_tag_clear" },
	{ 0x178fd99a, "kmem_cache_create" },
	{ 0xb3f7646e, "kthread_should_stop" },
	{ 0x9754ec10, "radix_tree_preload" },
	{ 0xf202c5cb, "radix_tree_insert" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "DE948EBE3175EBB925827A2");
