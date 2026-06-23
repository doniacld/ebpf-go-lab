/* Common BPF headers - simplified version that works without kernel headers */
#ifndef __COMMON_H__
#define __COMMON_H__

/* Basic type definitions */
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

/* BPF section macro */
#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* BPF map types */
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_RINGBUF 27

/* BPF helper attribute macros */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/* BPF update flags */
#define BPF_ANY 0

#endif /* __COMMON_H__ */
