#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bpf.h>
#include <linux/slab.h>
#include <linux/jhash.h>

typedef uint8_t* bitset_t;
bitset_t bitset_new(uint32_t size){
  return (bitset_t) kzalloc(1 + size/8,GFP_USER);
};

void bitset_set(bitset_t bs, uint32_t n){
  uint32_t B = n / 8;
  uint32_t b = n % 8;
  bs[B] = bs[B] | ((uint8_t)1 << b);
};

bool bitset_isset(bitset_t bs, uint32_t n){
  uint32_t B = n / 8;
  uint32_t b = n % 8;
  return ((bs[B] & (1 << b)) == ((uint8_t)1<<b));
};

void bitset_clear(bitset_t b){
};

typedef struct bloom {
  bitset_t bits;
  uint32_t m;
  uint8_t k;
}* bloom_t;

#define ceil(x, y) \
        ({ unsigned long __x = (x), __y = (y); (__x + __y - 1) / __y; })

/*
bloom_t bloom_new(uint64_t n, double fprate){
  double fillRatio = 0.5;

  bloom_t b = (bloom_t) kmalloc(sizeof(bloom_t),GFP_USER);

  b->m = (uint32_t) ceil((double)n / (log10(fillRatio) *
                  log10(1-fillRatio)) / fabs(log(fprate)));
  b->k = (uint8_t) ceil(log2(1/fprate));

  b->bits = bitset_new(b->m);

  return b;
}

bool bloom_test(bloom_t b, void* key, uint32_t len){
  uint32_t h=0,l=0;
  hashlittle2(key,len,&h,&l);
  
  // Check the K bits.
  for (uint32_t i = 0; i < b->k; i++ ){
    if (!bitset_isset(b->bits,(l+h*i) % b->m))
      return false;
  }

  return true;
};

void bloom_add(bloom_t b, void* key, uint32_t len){
  uint32_t h=0,l=0;
  hashlittle2(key,len,&h,&l);

  // Set the K bits.
  for (uint32_t i = 0; i < b->k; i++ ){
    bitset_set(b->bits,(l+h*i) % b->m);
  }
  b->count++;
};
*/

struct bpf_bloom {
	struct bpf_map map;
	spinlock_t lock;
        bitset_t bits;
        uint32_t m; // Number of buckets
        uint8_t k;  // Number of hashes
};

/* Called from syscall */
static struct bpf_map *bloom_map_alloc(union bpf_attr *attr)
{
	struct bpf_bloom *bloom;
	int err, i;

	bloom = kzalloc(sizeof(*bloom), GFP_USER);
	if (!bloom)
		return ERR_PTR(-ENOMEM);

//	/* mandatory map attributes */
//	bloom->map.key_size = attr->key_size;
//	bloom->map.value_size = attr->value_size;
//	bloom->map.max_entries = attr->max_entries;
//
//	/* check sanity of attributes.
//	 * value_size == 0 may be allowed in the future to use map as a set
//	 */
//	err = -EINVAL;
//	if (bloom->map.max_entries == 0 || bloom->map.key_size == 0 ||
//	    bloom->map.value_size == 0)
//		goto free_bloom;
//
//	/* hash table size must be power of 2 */
//	bloom->n_buckets = roundup_pow_of_two(bloom->map.max_entries);
//
//	err = -E2BIG;
//	if (bloom->map.key_size > MAX_BPF_STACK)
//		/* eBPF programs initialize keys on stack, so they cannot be
//		 * larger than max stack size
//		 */
//		goto free_bloom;
//
//	err = -ENOMEM;
//	/* prevent zero size kmalloc and check for u32 overflow */
//	if (bloom->n_buckets == 0 ||
//	    bloom->n_buckets > U32_MAX / sizeof(struct hlist_head))
//		goto free_bloom;
//
//	bloom->buckets = kmalloc_array(bloom->n_buckets, sizeof(struct hlist_head),
//				      GFP_USER | __GFP_NOWARN);
//
//	if (!bloom->buckets) {
//		bloom->buckets = vmalloc(bloom->n_buckets * sizeof(struct hlist_head));
//		if (!bloom->buckets)
//			goto free_bloom;
//	}
//
//	for (i = 0; i < bloom->n_buckets; i++)
//		INIT_HLIST_HEAD(&bloom->buckets[i]);
//
//	spin_lock_init(&bloom->lock);
//	bloom->count = 0;
//
//	bloom->elem_size = sizeof(struct bloom_elem) +
//			  round_up(bloom->map.key_size, 8) +
//			  bloom->map.value_size;
//
	return &bloom->map;

free_bloom:
	kfree(bloom);
	return ERR_PTR(err);
}

/* Called from syscall or from eBPF program */
static void *bloom_map_lookup_elem(struct bpf_map *map, void *key)
{
        printk("* In function %s *\n", __FUNCTION__);
	return NULL;
}

/* Called from syscall */
static int bloom_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	return -ENOENT;
}

/* Called from syscall or from eBPF program */
static int bloom_map_update_elem(struct bpf_map *map, void *key, void *value,
				u64 map_flags)
{
        printk("* In function %s *\n", __FUNCTION__);
  return -ENOENT;
}

/* Called from syscall or from eBPF program */
static int bloom_map_delete_elem(struct bpf_map *map, void *key)
{
        printk("* In function %s *\n", __FUNCTION__);
  return -ENOENT;
}

static void delete_all_elements(struct bpf_bloom *bloom)
{
}

/* Called when map->refcnt goes to zero, either from workqueue or from syscall */
static void bloom_map_free(struct bpf_map *map)
{
        printk("* In function %s *\n", __FUNCTION__);
}

static const struct bpf_map_ops bloom_ops = {
	.map_alloc = bloom_map_alloc,
	.map_free = bloom_map_free,
	.map_get_next_key = bloom_map_get_next_key,
	.map_lookup_elem = bloom_map_lookup_elem,
	.map_update_elem = bloom_map_update_elem,
	.map_delete_elem = bloom_map_delete_elem,
};

static struct bpf_map_type_list bloom_type __read_mostly = {
	.ops = &bloom_ops,
	.type = BPF_MAP_TYPE_BLOOM,
};

static int __init register_bloom_map(void) {
	bpf_register_map_type(&bloom_type);
	return 0;
}


late_initcall(register_bloom_map);
