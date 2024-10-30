#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "fraginfo.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 102400);
	__type(key, u64);
	__type(value, struct pgdat_info);
} nodes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 102400);
	__type(key, u64);
	__type(value, struct zone_info);
} zones SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 102400);
	__type(key,struct order_zone);
	__type(value, struct ctg_info);
} orders SEC(".maps");

static inline bool populated_zone(struct zone *zone)
{
	return zone->present_pages;
}
static void fill_contig_page_info(struct zone *zone, unsigned int suitable_order,
				  struct contig_page_info *info)
{
	unsigned int order;
	info->free_pages = 0;
	info->free_blocks_total = 0;
	info->free_blocks_suitable = 0;
	for (order = 0; order <= MAX_ORDER; order++) {
		unsigned long blocks;
		unsigned long nr_free;
		nr_free = BPF_CORE_READ(&zone->free_area[order], nr_free);
		blocks = nr_free;
		info->free_blocks_total += blocks;
		info->free_pages += blocks << order;
		if (order >= suitable_order)
			info->free_blocks_suitable += blocks << (order - suitable_order);
	}
}

SEC("kprobe/get_page_from_freelist")
int BPF_KPROBE(get_page_from_freelist, gfp_t gfp_mask, unsigned int order, int alloc_flags,
	       const struct alloc_context *ac)
{
	struct pgdat_info node_info = {};
	struct zone_info zone_data = {};

	struct pglist_data *pgdat;
	struct zoneref *zref;
	struct zone *z;
	int i;
	unsigned int a_order;
	int valid_nr_zones = 0;

	//节点信息
	pgdat = BPF_CORE_READ(ac, preferred_zoneref, zone, zone_pgdat);
	node_info.node_id = BPF_CORE_READ(pgdat, node_id);
	node_info.nr_zones = 0;
	node_info.pgdat_ptr = (u64)pgdat;
	u64 key = (u64)pgdat;
    
	// bpf_map_update_elem(&nodes, &key, &node_info, BPF_ANY);

	//遍历
	for (i = 0; i < __MAX_NR_ZONES; i++) {
		zref = &pgdat->node_zonelists[0]._zonerefs[i];
		z = BPF_CORE_READ(zref, zone);
		if ((u64)z == 0) break;
		int zone_node_id = BPF_CORE_READ(z, node);
		if (zone_node_id != node_info.node_id) {
            continue;  // 如果 zone 不属于当前 node，跳过
        }
		u64 present_pages = BPF_CORE_READ(z, present_pages);
		if (present_pages> 0) {
			valid_nr_zones++;
			zone_data.zone_ptr = (u64)z;
			zone_data.node_id=BPF_CORE_READ(z, node);
			u64 zone_key = (u64)z;
			zone_data.zone_start_pfn = BPF_CORE_READ(z, zone_start_pfn);
			zone_data.spanned_pages = BPF_CORE_READ(z, spanned_pages);
			zone_data.present_pages = present_pages;
			bpf_probe_read_kernel_str(zone_data.comm, sizeof(zone_data.comm), BPF_CORE_READ(z, name));
			for (a_order = 0; a_order <= MAX_ORDER; ++a_order) {
						zone_data.order = a_order;
						struct order_zone order_key = {};
						order_key.order = a_order;
						order_key.node_id= BPF_CORE_READ(z, node);
						if ((u64)z == 0) break;
						order_key.zone_ptr = (u64)z;
						
						struct contig_page_info ctg_info = {};
						fill_contig_page_info(z, a_order, &ctg_info);
						bpf_map_update_elem(&orders,&order_key,&ctg_info,BPF_ANY);
			}
					
			bpf_map_update_elem(&zones, &zone_key, &zone_data, BPF_ANY);
		}
	}
	node_info.nr_zones = valid_nr_zones;
	bpf_map_update_elem(&nodes, &key, &node_info, BPF_ANY);

	return 0;
}