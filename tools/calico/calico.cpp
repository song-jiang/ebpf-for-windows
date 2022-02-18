// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <io.h>
#include <iostream>
#include <string>
#include <windows.h>
#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include "ebpf_api.h"

const char* trace_map = "calico_xdp::trace_map";

const char* program_path = "calico_xdp::program";
const char* program_link = "calico_xdp::program_link";

typedef int16_t __s16;
typedef int32_t __s32;

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef uint32_t pid_t;

#define __bitwise__
#define __bitwise __bitwise__

typedef __u16 __bitwise __le16;
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __le32;
typedef __u32 __bitwise __be32;
typedef __u64 __bitwise __le64;
typedef __u64 __bitwise __be64;

typedef __u16 __sum16;


struct calico_ct_result
{
    __s16 rc;
    __u16 flags;
    __be32 nat_ip;
    __u16 nat_port;
    __u16 nat_sport;
    __be32 tun_ip;
    __u32 ifindex_fwd;     /* if set, the ifindex where the packet should be forwarded */
    __u32 ifindex_created; /* For a CT state that was created by a packet ingressing
                            * through an interface towards the host, this is the
                            * ingress interface index.  For a CT state created by a
                            * packet _from_ the host, it's CT_INVALID_IFINDEX (0).
                            */
};

struct calico_nat_dest
{
    __u32 addr;
    __u16 port;
    __u8 pad[2];
};

// struct cali_tc_state holds state that is passed between the BPF programs.
// WARNING: must be kept in sync with
// - the definitions in bpf/polprog/pol_prog_builder.go.
// - the Go version of the struct in bpf/state/map.go
struct cali_tc_state
{
    /* Initial IP read from the packet, updated to host's IP when doing NAT encap/ICMP error.
     * updated when doing CALI_CT_ESTABLISHED_SNAT handling. Used for FIB lookup. */
    __be32 ip_src;
    /* Initial IP read from packet. Updated when doing encap and ICMP errors or CALI_CT_ESTABLISHED_DNAT.
     * If connect-time load balancing is enabled, this will be the post-NAT IP because the connect-time
     * load balancer gets in before TC. */
    __be32 ip_dst;
    /* Set when invoking the policy program; if no NAT, ip_dst; otherwise, the pre-DNAT IP.  If the connect
     * time load balancer is enabled, this may be different from ip_dst. */
    __be32 pre_nat_ip_dst;
    /* If no NAT, ip_dst.  Otherwise the NAT dest that we look up from the NAT maps or the conntrack entry
     * for CALI_CT_ESTABLISHED_DNAT. */
    __be32 post_nat_ip_dst;
    /* For packets that arrived over our VXLAN tunnel, the source IP of the tunnel packet.
     * Zeroed out when we decide to respond with an ICMP error.
     * Also used to stash the ICMP MTU when calling the ICMP response program. */
    __be32 tun_ip;
    /* Return code from the policy program CALI_POL_DENY/ALLOW etc. */
    __s32 pol_rc;
    /* Source port of the packet; updated on the CALI_CT_ESTABLISHED_SNAT path or when doing encap.
     * zeroed out on the ICMP response path. */
    __u16 sport;
    union
    {
        /* dport is the destination port of the packet; it may be pre or post NAT */
        __u16 dport;
        struct icmp
        {
            __u8 icmp_type;
            __u8 icmp_code;
        };
    };
    /* Pre-NAT dest port; set similarly to pre_nat_ip_dst. */
    __u16 pre_nat_dport;
    /* Post-NAT dest port; set similarly to post_nat_ip_dst. */
    __u16 post_nat_dport;
    /* Packet IP proto; updated to UDP when we encap. */
    __u8 ip_proto;
    /* Flags from enum cali_state_flags. */
    __u8 flags;
    /* Packet size filled from iphdr->tot_len in tc_state_fill_from_iphdr(). */
    __be16 ip_size;

    /* Result of the conntrack lookup. */
    struct calico_ct_result ct_result;

    /* Result of the NAT calculation.  Zeroed if there is no DNAT. */
    struct calico_nat_dest nat_dest;
    __u64 prog_start_time;
};

typedef struct _process_entry
{
    uint32_t count;
    wchar_t name[32];
} process_entry_t;

void
get_addr(char *addr, __be32 ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    (void)sprintf_s(addr, 20, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

int
load(int argc, char** argv)
{
    const char* error_message = NULL;
    ebpf_result_t result;
    bpf_object* object = nullptr;
    bpf_program* program = nullptr;
    bpf_link* link = nullptr;
    fd_t program_fd;
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    result = ebpf_program_load(
        "xdp.o", nullptr, nullptr, EBPF_EXECUTION_JIT, &object, &program_fd, &error_message);
    if (result != EBPF_SUCCESS) {
        fprintf(stderr, "Failed to load calico xdp eBPF program\n");
        fprintf(stderr, "%s", error_message);
        ebpf_free_string(error_message);
        return 1;
    }

    fd_t trace_map_fd = bpf_object__find_map_fd_by_name(object, "trace_map");
    if (trace_map_fd <= 0) {
        fprintf(stderr, "Failed to find eBPF map : %s\n", trace_map);
        return 1;
    }

    if (bpf_obj_pin(trace_map_fd, trace_map) < 0) {
        fprintf(stderr, "Failed to pin eBPF program: %d\n", errno);
        return 1;
    }

    program = bpf_program__next(nullptr, object);
    if (program == nullptr) {
        fprintf(stderr, "Failed to find eBPF program from object.\n");
        return 1;
    }
    result = ebpf_program_attach(program, &EBPF_ATTACH_TYPE_XDP, nullptr, 0, &link);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to attach eBPF program\n");
        return 1;
    }

    if (bpf_link__pin(link, program_link) < 0) {
        fprintf(stderr, "Failed to pin eBPF link: %d\n", errno);
        return 1;
    }

    if (bpf_program__pin(program, program_path) < 0) {
        fprintf(stderr, "Failed to pin eBPF program: %d\n", errno);
        return 1;
    }

    return 0;
}

int
unload(int argc, char** argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    ebpf_object_unpin(program_path);
    ebpf_object_unpin(program_link);
    ebpf_object_unpin(trace_map);
    return 1;
}

int
stats(int argc, char** argv)
{
    fd_t map_fd;
    int result;
    __be32 pid;
    struct cali_tc_state state_entry;
    char src_addr[20], dest_addr[20], action[20], key[20];

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    map_fd = bpf_obj_get((char*)trace_map);
    if (map_fd == ebpf_fd_invalid) {
        fprintf(stderr, "Failed to look up eBPF map\n");
        return 1;
    }

    printf("Flags\t  SrcIP\t\t  DestIP\tProto\tkey\n");
    result = bpf_map_get_next_key(map_fd, nullptr, &pid);
    while (result == EBPF_SUCCESS) {
        memset(&state_entry, 0, sizeof(state_entry));
        result = bpf_map_lookup_elem(map_fd, &pid, &state_entry);
        if (result != EBPF_SUCCESS) {
            fprintf(stderr, "Failed to look up eBPF map entry: %d\n", result);
            return 1;
        }
        get_addr(src_addr, state_entry.ip_src);
        get_addr(dest_addr, state_entry.ip_dst);
        get_addr(key, pid);

        if (state_entry.flags == 8) {
            (void)sprintf_s(action, 20, "%s", "allow"); 
        }
        if (state_entry.flags == 9) {
            (void)sprintf_s(action, 20, "%s", "deny");
        }
        printf("%d\t%s\t%s\t%d\t[%s]\t\t%s\n", state_entry.flags, src_addr, dest_addr, state_entry.ip_proto, key, action);
        result = bpf_map_get_next_key(map_fd, &pid, &pid);
    };
    _close(map_fd);
    return 0;
}

int
limit(int argc, char** argv)
{
    uint32_t value;
    if (argc == 0) {
        fprintf(stderr, "limit requires a numerical value\n");
        return 1;
    }
    value = atoi(argv[0]);

    fd_t map_fd;
    uint32_t result;
    uint32_t key = 0;

    map_fd = bpf_obj_get((char*)trace_map); // NOT USED
    if (map_fd == ebpf_fd_invalid) {
        fprintf(stderr, "Failed to look up eBPF map.\n");
        return 1;
    }

    result = bpf_map_update_elem(map_fd, &key, &value, EBPF_ANY);
    if (result != EBPF_SUCCESS) {
        fprintf(stderr, "Failed to update eBPF map element: %d\n", result);
        return 1;
    }

    _close(map_fd);

    return 0;
}

typedef int (*operation_t)(int argc, char** argv);
struct
{
    const char* name;
    const char* help;
    operation_t operation;
} commands[]{
    {"load", "load\tLoad the calico eBPF program xdp.o", load},
    {"unload", "unload\tUnload the calico eBPF program xdp.o", unload},
    {"stats", "stats\tShow stats from the calico eBPF program", stats}};
    //{"limit", "limit value\tSet the port quota limit", limit}};

void
print_usage(char* path)
{
    fprintf(stderr, "Usage: %s command\n", path);
    for (auto& cmd : commands) {
        fprintf(stderr, "\t%s\n", cmd.name);
    }
}

int
main(int argc, char** argv)
{
    uint32_t result = ebpf_api_initiate();
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "ebpf_api_initiate failed: %d\n", result);
        return 1;
    }

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    for (const auto& cmd : commands) {
        if (_stricmp(cmd.name, argv[1]) == 0) {
            return cmd.operation(argc - 2, argv + 2);
        }
    }
    print_usage(argv[0]);
    return 1;
}
