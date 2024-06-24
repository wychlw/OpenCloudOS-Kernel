#ifndef AEGIS_MODULE_LIST_H_
#define AEGIS_MODULE_LIST_H_

#define HOOK_INFO_READ_FLAG 0x5a5a5a5a
extern void hookinfo_list_in(struct list_head *new, int type);
extern int list_module_init(void);
extern void list_module_exit(void);
extern void data_release(struct kref *ref);
extern void hook_info_func_unregister(void);

#endif  // AEGIS_MODULE_LIST_H_
