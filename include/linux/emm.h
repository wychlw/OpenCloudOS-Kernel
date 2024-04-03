#include <linux/memcontrol.h>

#ifdef CONFIG_EMM_MEMCG

struct emm_memcg_ops {
	int (*init)(struct mem_cgroup *memcg);
	void (*exit)(struct mem_cgroup *memcg);
};

int emm_memcg_init(struct mem_cgroup *memcg);
void emm_memcg_exit(struct mem_cgroup *memcg);

int emm_init(struct emm_memcg_ops *ops);
int emm_exit(void);

#else

static inline int emm_memcg_init(struct mem_cgroup *memcg)
{
	return 0;
}

static inline void emm_memcg_exit(struct mem_cgroup *memcg)
{
}

#endif

#ifdef CONFIG_EMM_RECLAIM

enum {
	EMM_RECLAIM,
	EMM_AGE,
	EMM_MIX,
};

#endif
