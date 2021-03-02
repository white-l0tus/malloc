# cglibc 2.23 malloc() 분석

시스템해킹을 공부하면서 heap exploitation에 많은 어려움을 겪고 있는데, malloc과 free의 작동 원리에 대해 면밀히 파헤침으로써 공부에 도움을 얻고자 glibc malloc.c 분석을 진행한다.

힙을 처음 접하는 사람도 이해할 수 있도록 최대한 자세히 설명하도록 노력하고 있으며, malloc.c에 정의되어 있지 않거나 따로 정리가 필요한 함수가 등장할 경우에는 후미의 Background에 따로 용도와 기능을 설명해 놓았다.

2021-03-02 현재진행중.

## malloc & free

### __libc_malloc

```c
void *__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));

  arena_get (ar_ptr, bytes);

  victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }

  if (ar_ptr != NULL)
    (void) mutex_unlock (&ar_ptr->mutex);

  assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
  return victim;
}
```

프로그램에서 할당할 메모리의 크기를 인자로 malloc을 호출할 경우 libc_malloc이 실행된다.  이 함수는 처음에 malloc_hook이 NULL인지 확인하고, 그렇지 않다면 hook에 적힌 함수를 대신 실행한다. (이 과정을 이용한 기법으로 **hook overwrite**이 존재한다.) 이후 arena_get을 통해 사용할 arena의 주소를 받아오고 나서_int_malloc을 호출하고 할당된 메모리의 주소를 victim에 담아 반환한다.

### _int_malloc: init

```c
static void *_int_malloc (mstate av, size_t bytes)
{
  INTERNAL_SIZE_T nb;               /* normalized request size */
  unsigned int idx;                 /* associated bin index */
  mbinptr bin;                      /* associated bin */

  mchunkptr victim;                 /* inspected/selected chunk */
  INTERNAL_SIZE_T size;             /* its size */
  int victim_index;                 /* its bin index */

  mchunkptr remainder;              /* remainder from a split */
  unsigned long remainder_size;     /* its size */

  unsigned int block;               /* bit map traverser */
  unsigned int bit;                 /* bit map traverser */
  unsigned int map;                 /* current word of binmap */

  mchunkptr fwd;                    /* misc temp for linking */
  mchunkptr bck;                    /* misc temp for linking */

  const char *errstr = NULL;

  /*
     Convert request size to internal form by adding SIZE_SZ bytes
     overhead plus possibly more to obtain necessary alignment and/or
     to obtain a size of at least MINSIZE, the smallest allocatable
     size. Also, checked_request2size traps (returning 0) request sizes
     that are so large that they wrap around zero when padded and
     aligned.
   */

  checked_request2size (bytes, nb);

  /* There are no usable arenas.  Fall back to sysmalloc to get a chunk from
     mmap.  */
  if (__glibc_unlikely (av == NULL))
    {
      void *p = sysmalloc (nb, av);
      if (p != NULL)
	alloc_perturb (p, bytes);
      return p;
    }
    
  /* ------------------ omitted ------------------  */
    
}
```

_int_malloc 내부에서는 가장 먼저 checked_request2size를 통해 요청된 크기를 아키텍처에 맞게 수정한다. 이 절에서는 malloc_chunk의 구조와 메모리 정렬 등에 대해 다룰 것이다.

- [SIZE_SZ](#SIZE_SZ)
- [MALLOC_ALIGNMENT](#MALLOC_ALIGNMENT)
- [Chunk representations](#Chunk-representations)
- [Conversions](#Conversions)
- [Size and alignment checks](#Size-and-alignment-checks)

### __libc_free

```c
void __libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      (*hook)(mem, RETURN_ADDRESS (0));
      return;
    }

  if (mem == 0)                              /* free(0) has no effect */
    return;

  p = mem2chunk (mem);

  if (chunk_is_mmapped (p))                       /* release mmapped memory. */
    {
      /* see if the dynamic brk/mmap threshold needs adjusting */
      if (!mp_.no_dyn_threshold
          && p->size > mp_.mmap_threshold
          && p->size <= DEFAULT_MMAP_THRESHOLD_MAX)
        {
          mp_.mmap_threshold = chunksize (p);
          mp_.trim_threshold = 2 * mp_.mmap_threshold;
          LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2,
                      mp_.mmap_threshold, mp_.trim_threshold);
        }
      munmap_chunk (p);
      return;
    }

  ar_ptr = arena_for_chunk (p);
  _int_free (ar_ptr, p, 0);
}
```

메모리 주소를 인자로 free를 호출할 경우 libc_free가 실행된다.  malloc과 마찬가지로 이 함수는 free_hook이 NULL인지 확인하고, 그렇지 않다면 hook에 적힌 함수를 대신 실행한다. 이후 mem2chunk를 통해 힙 청크의 주소를 받아오고, 청크가 mmap되어있지 않다면 _int_free를 호출한다.

### _int_free: init

```c
static void _int_free (mstate av, mchunkptr p, int have_lock)
{
  INTERNAL_SIZE_T size;        /* its size */
  mfastbinptr *fb;             /* associated fastbin */
  mchunkptr nextchunk;         /* next contiguous chunk */
  INTERNAL_SIZE_T nextsize;    /* its size */
  int nextinuse;               /* true if nextchunk is used */
  INTERNAL_SIZE_T prevsize;    /* size of previous contiguous chunk */
  mchunkptr bck;               /* misc temp for linking */
  mchunkptr fwd;               /* misc temp for linking */

  const char *errstr = NULL;
  int locked = 0;

  size = chunksize (p);

  /* Little security check which won't hurt performance: the
     allocator never wrapps around at the end of the address space.
     Therefore we can exclude some size values which might appear
     here by accident or by "design" from some intruder.  */
  if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    {
      errstr = "free(): invalid pointer";
    errout:
      if (!have_lock && locked)
        (void) mutex_unlock (&av->mutex);
      malloc_printerr (check_action, errstr, chunk2mem (p), av);
      return;
    }
  /* We know that each chunk is at least MINSIZE bytes in size or a
     multiple of MALLOC_ALIGNMENT.  */
  if (__glibc_unlikely (size < MINSIZE || !aligned_OK (size)))
    {
      errstr = "free(): invalid size";
      goto errout;
    }

  check_inuse_chunk(av, p);
  
  /* ------------------ omitted ------------------  */
}
```

_int_free는 시작 부분에서 chunksize를 통해 청크의 크기를 구한 뒤 간단한 검증 과정을 거친다. check_inuse_chunk는 [MALLOC_DEBUG](#MALLOC_DEBUG)가 0일 경우 실행되지 않는다.

##### free(): invalid pointer

청크의 주소가 16-byte aligned되어있지 않거나 청크의 끝이 가능한 주소 영역을 벗어났는지 검증한다.

##### free(): invalid size

청크의 크기가 16-byte aligned되어있지 않거나 MINSIZE보다 작은지 검증한다.

## Physical chunk operations

만약 이전 절에서 SIZE_BITS에 대한 설명을 읽지 않았다면 아래의 두 내용을 확인하는 것을 추천한다. chunk operations의 경우 앞으로 자주 등장하게 되므로 이름을 익혀두고 기능이 헷갈리거나 궁금할때 찾아보면 좋을 것이다.

- [SIZE_BITS](#SIZE_BITS)
- [chunk operations](#chunk operations)

## Arena

```c
struct malloc_state
{
  /* Serialize access.  */
  mutex_t mutex;

  /* Flags (formerly in max_fast).  */
  int flags;

  /* Fastbins */
  mfastbinptr fastbinsY[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr top;

  /* The remainder from the most recent split of a small request */
  mchunkptr last_remainder;

  /* Normal bins packed as described above */
  mchunkptr bins[NBINS * 2 - 2];

  /* Bitmap of bins */
  unsigned int binmap[BINMAPSIZE];

  /* Linked list */
  struct malloc_state *next;

  /* Linked list for free arenas.  Access to this field is serialized
     by free_list_lock in arena.c.  */
  struct malloc_state *next_free;

  /* Number of threads attached to this arena.  0 if the arena is on
     the free list.  Access to this field is serialized by
     free_list_lock in arena.c.  */
  INTERNAL_SIZE_T attached_threads;

  /* Memory allocated from the system in this arena.  */
  INTERNAL_SIZE_T system_mem;
  INTERNAL_SIZE_T max_system_mem;
};
```

arena란 힙 영역을 관리하는 구조체로, ptmalloc에서는 스레드별로 관리하여 main arena, thread arena가 존재한다. arena의 구조체는 malloc_state로 표현되며 fastbin, top, last_remainder 등의 정보를 담고 있다.

단일 스레딩 환경에서는 main_arena만 존재하기 때문에 앞으로 main_arena와 관련된 부분을 위주로 설명하도록 하겠다.

## Fastbins

```c
/*
   Fastbins

    An array of lists holding recently freed small chunks.  Fastbins
    are not doubly linked.  It is faster to single-link them, and
    since chunks are never removed from the middles of these lists,
    double linking is not necessary. Also, unlike regular bins, they
    are not even processed in FIFO order (they use faster LIFO) since
    ordering doesn't much matter in the transient contexts in which
    fastbins are normally used.

    Chunks in fastbins keep their inuse bit set, so they cannot
    be consolidated with other free chunks. malloc_consolidate
    releases all chunks in fastbins and consolidates them with
    other free chunks.
 */
```

fastbin은 최근에 free된 작은 크기의 청크들을 들고 있는 배열이며, 해제된 청크는 크기별로 나뉘어 LIFO 형식의 단일 연결 리스트로 관리된다. 또한 fastbin 크기의 청크는 해제하더라도 inuse bit를 변경하지 않아 다른 해제된 청크와 병합되는 것을 방지한다.

```python
(0x20)       fastbin[0]: 0x0
(0x30)       fastbin[1]: 0x0
(0x40)       fastbin[2]: 0x0
(0x50)       fastbin[3]: 0x0
(0x60)       fastbin[4]: 0x0
(0x70)       fastbin[5]: 0x0
(0x80)       fastbin[6]: 0x0
```

예를 들어 0x6000과 0x6030에 위치한 0x30 크기의 힙이 순서대로 해제된 상황을 보자.

```python
(0x20)       fastbin[0]: 0x0
(0x30)       fastbin[1]: 0x6030 -> 0x6000
(0x40)       fastbin[2]: 0x0
(0x50)       fastbin[3]: 0x0
(0x60)       fastbin[4]: 0x0
(0x70)       fastbin[5]: 0x0
(0x80)       fastbin[6]: 0x0
```

이 경우 나중에 해제된 0x6030이 연결 리스트의 head에 위치할 것이다. 만약 이 상태에서 malloc(0x28)을 호출한다면 어떻게 될까?

```python
(0x20)       fastbin[0]: 0x0
(0x30)       fastbin[1]: 0x6000
(0x40)       fastbin[2]: 0x0
(0x50)       fastbin[3]: 0x0
(0x60)       fastbin[4]: 0x0
(0x70)       fastbin[5]: 0x0
(0x80)       fastbin[6]: 0x0
    
0x6030:   chunk     ->     0x0000000000000000      0x0000000000000031
0x6040:   mem       ->     0x0000000000000000      0x0000000000000000
```

주어진 요청에 알맞은 청크의 크기는 0x30이고, fastbin에 동일한 크기의 청크가 존재하므로 저장해뒀던 청크를 할당해주게 될 것이다.

이처럼 fastbin은 이름 그대로 작은 크기의 힙이 반복되어 할당 및 해제될 때 빠른 작업을 가능하게 한다. 

```c
/* Maximum size of memory handled in fastbins.  */
static INTERNAL_SIZE_T global_max_fast;

/*
   Set value of max_fast.
   Use impossibly small value if 0.
   Precondition: there are no existing fastbin chunks.
   Setting the value clears fastchunk bit but preserves noncontiguous bit.
 */

#define set_max_fast(s) \
  global_max_fast = (((s) == 0)						      \
                     ? SMALLBIN_WIDTH : ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK))
#define get_max_fast() global_max_fast
```

get_max_fast는 fastbin의 최대 크기를 반환하는 매크로이다. global_max_fast는 아래와 같이 set_max_fast에 의해 16 * SIZE_SZ로 지정된다.

```c
#ifndef DEFAULT_MXFAST
#define DEFAULT_MXFAST     (64 * SIZE_SZ / 4)
#endif

static void malloc_init_state (mstate av)
{
  /* ------------------ omitted ------------------  */  
    
  if (av == &main_arena)
    set_max_fast (DEFAULT_MXFAST);
    
  /* ------------------ omitted ------------------  */
}
```

기본적으로 x86에서는 64byte, x64에서는 128byte가 fastbin의 최대 크기가 된다.

```c
typedef struct malloc_chunk *mfastbinptr;
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[idx])

/* offset 2 to use otherwise unindexable first 2 bins */
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)
```

fastbin은 주어진 아레나의 idx번째 fastbin에 적힌 주소를 반환한다. fastbin_index는 주어진 크기의 청크가 fastbin의 몇 번째 인덱스에 저장되어야 하는지 알려주는데, 가장 작은 크기인 0x20이 0번 인덱스에 배치되는 것을 볼 수 있다.

```c
/* The maximum fastbin request size we support */
#define MAX_FAST_SIZE     (80 * SIZE_SZ / 4)

#define NFASTBINS  (fastbin_index (request2size (MAX_FAST_SIZE)) + 1)
```

MAX_FAST_SIZE는 라이브러리에서 지원하는 fastbin의 최대 메모리 크기이고, NFASTBINS는 이에 따라 만들어야 할 fastbin 배열의 크기이다.

```python
(0x20)       fastbin[0]: 0x0
(0x30)       fastbin[1]: 0x0
(0x40)       fastbin[2]: 0x0
(0x50)       fastbin[3]: 0x0
(0x60)       fastbin[4]: 0x0
(0x70)       fastbin[5]: 0x0
(0x80)       fastbin[6]: 0x0
(0x90)       fastbin[7]: 0x0
(0xa0)       fastbin[8]: 0x0
(0xb0)       fastbin[9]: 0x0
```

결국 x64에서 이론상 가능한 fastbin chunk의 최대 크기는 0xb0이고, 위와 같이 pwngdb의 heapinfo가 fastbin을 0xb0까지 보여주는 것은 이 때문인듯 하다.

### _int_free: fastbin

```c
  /*
    If eligible, place chunk on a fastbin so it can be found
    and used quickly in malloc.
  */

  if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())

#if TRIM_FASTBINS
      /*
	If TRIM_FASTBINS set, don't place chunks
	bordering top into fastbins
      */
      && (chunk_at_offset(p, size) != av->top)
#endif
      ) 
  {
 
      /* ------------------ omitted ------------------  */

  }
```

free된 청크가 fastbin 크기에 해당하면 청크를 fastbin에 집어넣는 과정이 진행된다. 이때 TRIM_FASTBINS가 설정되어 있으면 top chunk와 인접한 청크는 fastbin에 집어넣지 않게 되는데, 기본값은 0이므로 큰 상관은 없다.

##### free(): invalid next size (fast)

```c
    if (__builtin_expect (chunk_at_offset (p, size)->size <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (chunksize (chunk_at_offset (p, size))
			     >= av->system_mem, 0))
    {
	/* We might not have a lock at this point and concurrent modifications
	   of system_mem might have let to a false positive.  Redo the test
	   after getting the lock.  */
	  if (have_lock
	    || ({ assert (locked == 0); mutex_lock(&av->mutex); locked = 1;
		  chunk_at_offset (p, size)->size <= 2 * SIZE_SZ
		    || chunksize (chunk_at_offset (p, size)) >= av->system_mem;
	      }))
	  {
	    errstr = "free(): invalid next size (fast)";
	    goto errout;
	  }
	  if (! have_lock)
	  {
	    (void)mutex_unlock(&av->mutex);
	    locked = 0;
	  }
    }
```

만약 해제한 청크 다음에 존재하는 청크의 크기가 2 * SIZE_SZ 이하 혹은 av->system_mem 이상일 경우 출력되는 에러이다. system_mem은 main_arena의 경우 128kb, 즉 0x20000을 기본값으로 가진다.

##### double free or corruption (fasttop)

```c
    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);

    set_fastchunks(av);
    unsigned int idx = fastbin_index(size);
    fb = &fastbin (av, idx);

    /* Atomically link P to its fastbin: P->FD = *FB; *FB = P;  */
    mchunkptr old = *fb, old2;
    unsigned int old_idx = ~0u;
    do
    {
	/* Check that the top of the bin is not the record we are going to add
	   (i.e., double free).  */
	  if (__builtin_expect (old == p, 0))
	  {
	    errstr = "double free or corruption (fasttop)";
	    goto errout;
	  }
	/* Check that size of fastbin chunk at the top is the same as
	   size of the chunk that we are adding.  We can dereference OLD
	   only if we have the lock, otherwise it might have already been
	   deallocated.  See use of OLD_IDX below for the actual check.  */
	   if (have_lock && old != NULL)
	 	 old_idx = fastbin_index(chunksize(old));
	   p->fd = old2 = old;
    }
    while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2)) != old2);
```

[free_perturb](#perturb)는 디버깅 용도가 아닐 경우 실행되지 않고, set_fastchunks는 아레나의 FASTCHUNKS_BIT를 0으로 만드는 역할을 한다. 이후 fastbinsY[idx]에 적혀 있던 주소를 old에 담고 double free 검증을 실시한다. 

만약 old와 p가 같을 경우, 이미 fastbin의 top에 존재하는 청크를 한 번 더 해제하려는 시도이므로 에러 메세지를 출력하게 된다. 그렇지 않다면 p의 fd에 old를 적고, fastbinsY[idx]에 p를 적은 이후 while문을 빠져나온다.

[catomic_compare_and_exchange_val_rel](#__sync_val_compare_and_swap)같은 함수가 종료 조건에 포함된 do while문을 라이브러리 내부에서 자주 관찰할 수 있는데, race condition을 예방하기 위한 구현으로 보인다.

##### invalid fastbin entry (free)

```c
    if (have_lock && old != NULL && __builtin_expect (old_idx != idx, 0))
      {
	errstr = "invalid fastbin entry (free)";
	goto errout;
      }
```

lock이 걸려 있을 경우 fastbin의 top에 있는 청크의 크기와 추가하고자 하는 청크의 크기가 일치하는지 검증한다.

### _int_malloc: fastbin

```c
  /*
     If the size qualifies as a fastbin, first check corresponding bin.
     This code is safe to execute even if av is not yet initialized, so we
     can try it without checking, which saves some time on this fast path.
   */

  if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))
    {
      idx = fastbin_index (nb);
      mfastbinptr *fb = &fastbin (av, idx);
      mchunkptr pp = *fb;
      do
        {
          victim = pp;
          if (victim == NULL)
            break;
        }
      while ((pp = catomic_compare_and_exchange_val_acq (fb, victim->fd, victim))
             != victim);
      
      /* ------------------ omitted ------------------  */
      
    }
```

만약 요청에 부합하는 청크의 크기가 fastbin에 속한다면, fastbinsY[idx]에 청크가 존재하는지 확인한 뒤 victim에 저장한다. 만약 같은 크기의 청크가 fastbin에 없다면 조건문을 빠져나와 다른 방식으로 할당되게 된다.

##### malloc(): memory corruption (fast)

```c
      if (victim != 0)
        {
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);
              return NULL;
            }
          check_remalloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
```

할당하고자 하는 fastbin chunk의 size가 손상되었는지 검증한다. 만약 청크가 0x40 크기 fastbin에 들어있다면, size는 0x40~0x4f사이여야 한다.

별다른 문제가 없다면 _int_malloc은 할당한 청크의 주소인 p를 반환하면서 종료된다.

## Smallbin

### _int_malloc: smallbin

```c
  /*
     If a small request, check regular bin.  Since these "smallbins"
     hold one size each, no searching within bins is necessary.
     (For a large request, we need to wait until unsorted chunks are
     processed to find best fit. But for small ones, fits are exact
     anyway, so we can check now, which is faster.)
   */

  if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          if (victim == 0) /* initialization check */
            malloc_consolidate (av);
          else
            {
              bck = victim->bk;
	if (__glibc_unlikely (bck->fd != victim))
                {
                  errstr = "malloc(): smallbin double linked list corrupted";
                  goto errout;
                }
              set_inuse_bit_at_offset (victim, nb);
              bin->bk = bck;
              bck->fd = bin;

              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }
        }
    }
```

## Largebin

### _int_malloc: largebin

```c
  /*
     If this is a large request, consolidate fastbins before continuing.
     While it might look excessive to kill all fastbins before
     even seeing if there is space available, this avoids
     fragmentation problems normally associated with fastbins.
     Also, in practice, programs tend to have runs of either small or
     large requests, but less often mixtures, so consolidation is not
     invoked all that often in most programs. And the programs that
     it is called frequently in otherwise tend to fragment.
   */

  else
    {
      idx = largebin_index (nb);
      if (have_fastchunks (av))
        malloc_consolidate (av);
    }
```

## free check routines

```c
  /*
    Consolidate other non-mmapped chunks as they arrive.
  */

  else if (!chunk_is_mmapped(p)) {
    if (! have_lock) {
      (void)mutex_lock(&av->mutex);
      locked = 1;
    }

    nextchunk = chunk_at_offset(p, size);

    /* Lightweight tests: check whether the block is already the
       top block.  */
    if (__glibc_unlikely (p == av->top))
      {
	errstr = "double free or corruption (top)";
	goto errout;
      }
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    if (__builtin_expect (contiguous (av)
			  && (char *) nextchunk
			  >= ((char *) av->top + chunksize(av->top)), 0))
      {
	errstr = "double free or corruption (out)";
	goto errout;
      }
    /* Or whether the block is actually not marked used.  */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      {
	errstr = "double free or corruption (!prev)";
	goto errout;
      }

    nextsize = chunksize(nextchunk);
    if (__builtin_expect (nextchunk->size <= 2 * SIZE_SZ, 0)
	|| __builtin_expect (nextsize >= av->system_mem, 0))
      {
	errstr = "free(): invalid next size (normal)";
	goto errout;
      }

    free_perturb (chunk2mem(p), size - 2 * SIZE_SZ);
    
    /* ------------------ omitted ------------------  */

  }
  else {
    munmap_chunk (p);
  }
```

## Consolidate

```c
    /* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = p->prev_size;
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
    }

    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
	unlink(av, nextchunk, bck, fwd);
	size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0);

      /*
	Place the chunk in unsorted chunk list. Chunks are
	not placed into regular bins until after they have
	been given one chance to be used in malloc.
      */

      bck = unsorted_chunks(av);
      fwd = bck->fd;
      if (__glibc_unlikely (fwd->bk != bck))
	{
	  errstr = "free(): corrupted unsorted chunks";
	  goto errout;
	}
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
	{
	  p->fd_nextsize = NULL;
	  p->bk_nextsize = NULL;
	}
      bck->fd = p;
      fwd->bk = p;

      set_head(p, size | PREV_INUSE);
      set_foot(p, size);

      check_free_chunk(av, p);
    }

    /*
      If the chunk borders the current high end of memory,
      consolidate into top
    */

    else {
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
      check_chunk(av, p);
    }
```



## Background

##### **atomic_forced_read**

```c
#ifndef atomic_forced_read
# define atomic_forced_read(x) \
  ({ __typeof (x) __x; __asm ("" : "=r" (__x) : "0" (x)); __x; })
#endif
```

https://stackoverflow.com/questions/58082597/what-is-the-purpose-of-glibcs-atomic-forced-read-function

기능에 대한 이해가 잘 되지 않지만, 다른 프로세스나 스레드에 의한 값 변경을 방지하는 역할로 생각된다.

##### **__builtin_expect**

```c
/* Tell the compiler when a conditional or integer expression is
   almost always true or almost always false.  */
#ifndef HAVE_BUILTIN_EXPECT
# define __builtin_expect(expr, val) (expr)
#endif
```

컴파일러에게 주어진 expr의 값이 참과 거짓 중 어느 한 쪽이 많이 등장함을 알려줌으로써 조건문의 분기 예측 최적화에 도움을 준다. 자주 발생하지 않는 예외 등을 처리할 때 사용하면 프로그램 성능 향상을 기대할 수 있다.

##### **arena_get**

```c
/* arena_get() acquires an arena and locks the corresponding mutex.
   First, try the one last locked successfully by this thread.  (This
   is the common case and handled with a macro for speed.)  Then, loop
   once over the circularly linked list of arenas.  If no arena is
   readily available, create a new one.  In this latter case, `size'
   is just a hint as to how much memory will be required immediately
   in the new arena. */

#define arena_get(ptr, size) do { \
      ptr = thread_arena;						      \
      arena_lock (ptr, size);						      \
  } while (0)

#define arena_lock(ptr, size) do {					      \
      if (ptr && !arena_is_corrupt (ptr))				      \
        (void) mutex_lock (&ptr->mutex);				      \
      else								      \
        ptr = arena_get2 ((size), NULL);				      \
  } while (0)

/* find the heap and corresponding arena for a given ptr */

#define heap_for_ptr(ptr) \
  ((heap_info *) ((unsigned long) (ptr) & ~(HEAP_MAX_SIZE - 1)))
#define arena_for_chunk(ptr) \
  (chunk_non_main_arena (ptr) ? heap_for_ptr (ptr)->ar_ptr : &main_arena)
```

##### **arena_get2**

```c
static mstate
internal_function
arena_get2 (size_t size, mstate avoid_arena)
{
  mstate a;

  static size_t narenas_limit;

  a = get_free_list ();
  if (a == NULL)
    {
      /* Nothing immediately available, so generate a new arena.  */
      if (narenas_limit == 0)
        {
          if (mp_.arena_max != 0)
            narenas_limit = mp_.arena_max;
          else if (narenas > mp_.arena_test)
            {
              int n = __get_nprocs ();

              if (n >= 1)
                narenas_limit = NARENAS_FROM_NCORES (n);
              else
                /* We have no information about the system.  Assume two
                   cores.  */
                narenas_limit = NARENAS_FROM_NCORES (2);
            }
        }
    repeat:;
      size_t n = narenas;
      /* NB: the following depends on the fact that (size_t)0 - 1 is a
         very large number and that the underflow is OK.  If arena_max
         is set the value of arena_test is irrelevant.  If arena_test
         is set but narenas is not yet larger or equal to arena_test
         narenas_limit is 0.  There is no possibility for narenas to
         be too big for the test to always fail since there is not
         enough address space to create that many arenas.  */
      if (__glibc_unlikely (n <= narenas_limit - 1))
        {
          if (catomic_compare_and_exchange_bool_acq (&narenas, n + 1, n))
            goto repeat;
          a = _int_new_arena (size);
	  if (__glibc_unlikely (a == NULL))
            catomic_decrement (&narenas);
        }
      else
        a = reused_arena (avoid_arena);
    }
  return a;
}
```

##### **arena_get_retry**

```c
/* If we don't have the main arena, then maybe the failure is due to running
   out of mmapped areas, so we can try allocating on the main arena.
   Otherwise, it is likely that sbrk() has failed and there is still a chance
   to mmap(), so try one of the other arenas.  */
static mstate
arena_get_retry (mstate ar_ptr, size_t bytes)
{
  LIBC_PROBE (memory_arena_retry, 2, bytes, ar_ptr);
  if (ar_ptr != &main_arena)
    {
      (void) mutex_unlock (&ar_ptr->mutex);
      /* Don't touch the main arena if it is corrupt.  */
      if (arena_is_corrupt (&main_arena))
		return NULL;

      ar_ptr = &main_arena;
      (void) mutex_lock (&ar_ptr->mutex);
    }
  else
    {
      (void) mutex_unlock (&ar_ptr->mutex);
      ar_ptr = arena_get2 (bytes, ar_ptr);
    }

  return ar_ptr;
}
```

##### __sync_val_compare_and_swap

```c
#ifndef catomic_compare_and_exchange_val_rel
# ifndef atomic_compare_and_exchange_val_rel
#  define catomic_compare_and_exchange_val_rel(mem, newval, oldval)	      \
  catomic_compare_and_exchange_val_acq (mem, newval, oldval)
# else
#  define catomic_compare_and_exchange_val_rel(mem, newval, oldval)	      \
  atomic_compare_and_exchange_val_rel (mem, newval, oldval)
# endif
#endif
```

```c
#ifndef catomic_compare_and_exchange_val_acq
# ifdef __arch_c_compare_and_exchange_val_32_acq
#  define catomic_compare_and_exchange_val_acq(mem, newval, oldval) \
  __atomic_val_bysize (__arch_c_compare_and_exchange_val,acq,		      \
		       mem, newval, oldval)
# else
#  define catomic_compare_and_exchange_val_acq(mem, newval, oldval) \
  atomic_compare_and_exchange_val_acq (mem, newval, oldval)
# endif
#endif
```

이처럼 비슷한 이름의 함수들을 라이브러리에서 관찰할 수 있는데, 아키텍처마다 서로 다른 함수를 새로운 이름으로 재정의해서 사용하는 것으로 보인다.

```c
#define atomic_compare_and_exchange_val_acq(mem, newval, oldval) \
  __sync_val_compare_and_swap (mem, oldval, newval)
```

이는 [**sysdeps/x86_64/atomic-machine.h**](https://elixir.bootlin.com/glibc/glibc-2.23/source/sysdeps/x86_64/atomic-machine.h#L61)에 정의된 내용으로, __sync_val_compare_and_swap는 x86-64용 builtin function이다.

이는 mem의 값이 oldval과 동일하면 newval에 있는 값을 mem에 쓰는 함수이며, 함수 이름의 atomic와 sync는 수행 과정에서 다른 프로세스나 스레드가 mem, oldval, newval을 바꾸지 못한다는 것이 보장되어야 함을 의미한다고 한다. 또한 리턴값으로 기존에 mem이 가리키던 값을 반환한다.

#####  perturb

```c
/* ------------------ Testing support ----------------------------------*/

static int perturb_byte;

static void alloc_perturb (char *p, size_t n)
{
  if (__glibc_unlikely (perturb_byte))
    memset (p, perturb_byte ^ 0xff, n);
}

static void free_perturb (char *p, size_t n)
{
  if (__glibc_unlikely (perturb_byte))
    memset (p, perturb_byte, n);
}
```

```c
int __libc_mallopt (int param_number, int value)
{
  switch (param_number)
    {
    case M_PERTURB:
      LIBC_PROBE (memory_mallopt_perturb, 2, value, perturb_byte);
      perturb_byte = value;
      break;
	}
}
```

M_PERTURB가 0이 아닐 경우, malloc과 free에 의해 할당되고 해제되는 청크의 메모리 영역은 모두 perturb_byte로 채워지게 된다. 이 기능은 힙 영역을 디버깅할때 사용할 수 있다.

##### **SIZE_SZ**

```c
/*
  INTERNAL_SIZE_T is the word-size used for internal bookkeeping
  of chunk sizes.

  The default version is the same as size_t.

  While not strictly necessary, it is best to define this as an
  unsigned type, even if size_t is a signed type. This may avoid some
  artificial size limitations on some systems.

  On a 64-bit machine, you may be able to reduce malloc overhead by
  defining INTERNAL_SIZE_T to be a 32 bit `unsigned int' at the
  expense of not being able to handle more than 2^32 of malloced
  space. If this limitation is acceptable, you are encouraged to set
  this unless you are on a platform requiring 16byte alignments. In
  this case the alignment requirements turn out to negate any
  potential advantages of decreasing size_t word size.

  Implementors: Beware of the possible combinations of:
     - INTERNAL_SIZE_T might be signed or unsigned, might be 32 or 64 bits,
       and might be the same width as int or as long
     - size_t might have different width and signedness as INTERNAL_SIZE_T
     - int and long might be 32 or 64 bits, and might be the same width
  To deal with this, most comparisons and difference computations
  among INTERNAL_SIZE_Ts should cast them to unsigned long, being
  aware of the fact that casting an unsigned int to a wider long does
  not sign-extend. (This also makes checking for negative numbers
  awkward.) Some of these casts result in harmless compiler warnings
  on some systems.
*/

#ifndef INTERNAL_SIZE_T
#define INTERNAL_SIZE_T size_t
#endif

/* The corresponding word size */
#define SIZE_SZ                (sizeof(INTERNAL_SIZE_T))
```

INTERNAL_SIZE_T는 힙 청크를 관리하기 위해 정의되는 단위 자료형이고, 기본적으로는 size_t와 같다. size_t는 임의의 객체가 가질 수 있는 최대 크기를 나타내며 x86에서는 32bit, x64에서는 64bit 자료형이다. 따라서 SIZE_SZ는 x64에서 8byte라는 값을 가지게 된다.

##### **MALLOC_ALIGNMENT**

```c
/*
  MALLOC_ALIGNMENT is the minimum alignment for malloc'ed chunks.
  It must be a power of two at least 2 * SIZE_SZ, even on machines
  for which smaller alignments would suffice. It may be defined as
  larger than this though. Note however that code and data structures
  are optimized for the case of 8-byte alignment.
*/

#ifndef MALLOC_ALIGNMENT
# if !SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_16)
/* This is the correct definition when there is no past ABI to constrain it.

   Among configurations with a past ABI constraint, it differs from
   2*SIZE_SZ only on powerpc32.  For the time being, changing this is
   causing more compatibility problems due to malloc_get_state and
   malloc_set_state than will returning blocks not adequately aligned for
   long double objects under -mlong-double-128.  */

#  define MALLOC_ALIGNMENT       (2 *SIZE_SZ < __alignof__ (long double)      \
                                  ? __alignof__ (long double) : 2 *SIZE_SZ)
# else
#  define MALLOC_ALIGNMENT       (2 *SIZE_SZ)
# endif
#endif

/* The corresponding bit mask value */
#define MALLOC_ALIGN_MASK      (MALLOC_ALIGNMENT - 1)
```

C 언어의 기본 데이터 타입은 모두 자신의 크기와 동일한 정렬 제한을 가지므로, \__alignof__ (long double)은 16byte이고, 마찬가지로 malloc을 통해 할당되는 힙 청크 또한 16byte 단위로 메모리에 배치된다. 이 경우 MALLOC_ALIGN_MASK는 16진수로 0xf이고, 이를 이용해 나머지와 같은 연산을 비트 연산으로 대체할 수 있다.

##### **Chunk representations**

```c
/*
  This struct declaration is misleading (but accurate and necessary).
  It declares a "view" into memory allowing access to necessary
  fields at known offsets from a given base. See explanation below.
*/

struct malloc_chunk {

  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

힙 청크의 구조는 위와 같다. malloc의 동작을 이해하기 위해 꼭 알아야 하는 사실이 있는데, 사용자가 malloc을 통해 사용하는 주소는 청크의 주소와 다르다는 점을 짚고 넘어가야 한다.

```c
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of previous chunk, if allocated            | |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of chunk, in bytes                       |M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             User data starts here...                          .
	    .                                                               .
	    .             (malloc_usable_size() bytes)                      .
	    .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |             Size of chunk                                     |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```

이처럼 청크는 자신의 크기를 나타내는 size와 이전 청크의 크기를 나타내는 prev_size를 저장하고 있다. 이렇게 함으로써 파편화된 청크를 빠른 속도로 병합할 수 있게 된다고 한다.

##### Conversions

```c
/* conversion from malloc headers to user pointers, and back */

#define chunk2mem(p)   ((void*)((char*)(p) + 2*SIZE_SZ))
#define mem2chunk(mem) ((mchunkptr)((char*)(mem) - 2*SIZE_SZ))
```

따라서 메모리와 청크의 주소는 x64 기준 0x10 만큼 차이나게 되고, 이를 변환하기 위한 매크로가 존재한다.

##### Size and alignment checks

```c
/* The smallest possible chunk */
#define MIN_CHUNK_SIZE        (offsetof(struct malloc_chunk, fd_nextsize))

/* The smallest size we can malloc is an aligned minimal chunk */

#define MINSIZE  \
  (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))
```

MIN_CHUNK_SIZE를 보면 offsetof(struct malloc_chunk, fd_nextsize)로 정의되어 있다. 즉, 힙 청크의 최소 구성요소가 prev_size, size, fd, bk라는 뜻이다. 그러므로 MINSIZE는 0x20이 될 것이다.

```c
/* Check if m has acceptable alignment */

#define aligned_OK(m)  (((unsigned long)(m) & MALLOC_ALIGN_MASK) == 0)

#define misaligned_chunk(p) \
  ((uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem (p)) \
   & MALLOC_ALIGN_MASK)

/*
   Check if a request is so large that it would wrap around zero when
   padded and aligned. To simplify some other code, the bound is made
   low enough so that adding MINSIZE will also not wrap around zero.
 */

#define REQUEST_OUT_OF_RANGE(req)                                 \
  ((unsigned long) (req) >=						      \
   (unsigned long) (INTERNAL_SIZE_T) (-2 * MINSIZE))

/* pad request bytes into a usable size -- internal version */

#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

/*  Same, except also perform argument check */

#define checked_request2size(req, sz)                             \
  if (REQUEST_OUT_OF_RANGE (req)) {					      \
      __set_errno (ENOMEM);						      \
      return 0;								      \
    }									      \
  (sz) = request2size (req);
```

드디어 checked_request2size에 대해 알아볼 차례이다. request2size는 padding과 align을 통해 요청한 크기의 메모리를 담을 수 있는 청크의 크기를 반환한다. 기본적으로 ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)가 반환되며, 이는 (req) + SIZE_SZ보다 크거나 같은 16의 배수로 올림하는 것과 같다.

이때 힙 청크와 메모리의 주소 차이는 2*SIZE_SZ인데 왜 SIZE_SZ만큼만 더하는 것일까? 그 이유는 다음 청크의 prev_size를 메모리로 사용할 수 있기 때문이다.

만약 malloc(0x20)을 선언한다면 힙 청크는 다음과 같이 구성될 것이다.

```python
0x0:   chunk     ->     0x0000000000000000      0x0000000000000031
0x10:  mem       ->     0x0000000000000000      0x0000000000000000
0x20:                   0x0000000000000000      0x0000000000000000
0x30:  nextchunk ->     0x0000000000000000      0x0000000000000031
0x40:  nextmem   ->     0x0000000000000000      0x0000000000000000
```

0x10부터 32바이트가 할당되고, 청크의 size에는 0x31이 적혀있다. (청크 크기가 항상 8의 배수기 때문에 가장 아래쪽 세 개의 비트는 [다른 정보들](#size_bits)을 나타내는데 사용된다. 따라서 실제 크기는 0x30이라고 생각하면 된다.)

또한 메모리를 효율적으로 관리하기 위해 nextchunk는 청크 바로 다음에 붙어있는 것을 볼 수 있다.

그렇다면 malloc(0x28)을 선언하고 메모리를 모두 0x41로 채우면 어떻게 될까?

```python
0x0:   chunk     ->     0x0000000000000000      0x0000000000000031
0x10:  mem       ->     0x4141414141414141      0x4141414141414141
0x20:                   0x4141414141414141      0x4141414141414141
0x30:  nextchunk ->     0x4141414141414141      0x0000000000000031
0x40:  nextmem   ->     0x0000000000000000      0x0000000000000000
```

청크의 사이즈는 변하지 않았는데 0x28바이트가 입력되었으므로 입력한 0x41이 nextchunk를 침범하게 된다. 하지만 이는 의도된 것이다. nextchunk의 첫 8바이트는 prev_size에 해당하는데, 이 영역은 이전 청크가 free되었을 경우 그 크기를 저장하기 위해 사용된다. 따라서 아직 chunk가 사용중일 경우에는 prev_size에 무언가를 저장할 일이 없고, 이전 청크에서 이 영역을 이용할 수 있다.

그러므로 위 상황은 청크의 크기가 0x30이므로 메모리는 0x20밖에 안될 것 같지만, 다음 청크의 prev_size를 이용함으로써 총 0x28바이트의 메모리를 할당할 수 있게 된 것이다. 

따라서 0x19~0x28 사이의 크기로 요청이 들어오게 되면 알맞은 청크의 크기는 0x30이 될 것이고, 이를 계산하는 공식이 ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)임을 알 수 있다.

```c
#define request2size(req)                                         \
  (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
   MINSIZE :                                                      \
   ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
   
#define REQUEST_OUT_OF_RANGE(req)                                 \
  ((unsigned long) (req) >=						      \
   (unsigned long) (INTERNAL_SIZE_T) (-2 * MINSIZE))
```

예외 처리로 아주 작은 크기의 요청이 들어오는 경우에는 0x0이나 0x10이 아니라 힙 청크의 최소 크기인 0x20을 반환하고, -1과 같이 매우 큰 수가 들어오게 될 경우 REQUEST_OUT_OF_RANGE를 통해 청크의 크기가 0 근처로 할당되는 것을 방지한다.

##### SIZE_BITS

```c
/*
   --------------- Physical chunk operations ---------------
 */


/* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
#define PREV_INUSE 0x1

/* extract inuse bit of previous chunk */
#define prev_inuse(p)       ((p)->size & PREV_INUSE)


/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
#define IS_MMAPPED 0x2

/* check for mmap()'ed chunk */
#define chunk_is_mmapped(p) ((p)->size & IS_MMAPPED)


/* size field is or'ed with NON_MAIN_ARENA if the chunk was obtained
   from a non-main arena.  This is only set immediately before handing
   the chunk to the user, if necessary.  */
#define NON_MAIN_ARENA 0x4

/* check for chunk from non-main arena */
#define chunk_non_main_arena(p) ((p)->size & NON_MAIN_ARENA)

/*
   Bits to mask off when extracting size

   Note: IS_MMAPPED is intentionally not masked off from size field in
   macros for which mmapped chunks should never be seen. This should
   cause helpful core dumps to occur if it is tried by accident by
   people extending or adapting this malloc.
 */
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
```

청크 size의 하위 세 비트는 각각 PREV_INUSE, IS_MMAPPED, NON_MAIN_ARENA를 표현한다.

##### chunk operations

```c
/* Get size, ignoring use bits */
#define chunksize(p)         ((p)->size & ~(SIZE_BITS))

/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))

/* Ptr to previous physical malloc_chunk */
#define prev_chunk(p) ((mchunkptr) (((char *) (p)) - ((p)->prev_size)))

/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s)))

/* extract p's inuse bit */
#define inuse(p)							      \
  ((((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))->size) & PREV_INUSE)

/* set/clear chunk as being inuse without otherwise disturbing */
#define set_inuse(p)							      \
  ((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))->size |= PREV_INUSE

#define clear_inuse(p)							      \
  ((mchunkptr) (((char *) (p)) + ((p)->size & ~SIZE_BITS)))->size &= ~(PREV_INUSE)


/* check/set/clear inuse bits in known places */
#define inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->size & PREV_INUSE)

#define set_inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->size |= PREV_INUSE)

#define clear_inuse_bit_at_offset(p, s)					      \
  (((mchunkptr) (((char *) (p)) + (s)))->size &= ~(PREV_INUSE))


/* Set size at head, without disturbing its use bit */
#define set_head_size(p, s)  ((p)->size = (((p)->size & SIZE_BITS) | (s)))

/* Set size/use field */
#define set_head(p, s)       ((p)->size = (s))

/* Set size at footer (only when chunk is not in use) */
#define set_foot(p, s)       (((mchunkptr) ((char *) (p) + (s)))->prev_size = (s))
```

청크의 size를 이용한 다양한 연산을 담은 매크로이다.

##### MALLOC_DEBUG

```c
/*
   Debugging support

   These routines make a number of assertions about the states
   of data structures that should be true at all times. If any
   are not true, it's very likely that a user program has somehow
   trashed memory. (It's also possible that there is a coding error
   in malloc. In which case, please report it!)
 */

#if !MALLOC_DEBUG

# define check_chunk(A, P)
# define check_free_chunk(A, P)
# define check_inuse_chunk(A, P)
# define check_remalloced_chunk(A, P, N)
# define check_malloced_chunk(A, P, N)
# define check_malloc_state(A)

#else

# define check_chunk(A, P)              do_check_chunk (A, P)
# define check_free_chunk(A, P)         do_check_free_chunk (A, P)
# define check_inuse_chunk(A, P)        do_check_inuse_chunk (A, P)
# define check_remalloced_chunk(A, P, N) do_check_remalloced_chunk (A, P, N)
# define check_malloced_chunk(A, P, N)   do_check_malloced_chunk (A, P, N)
# define check_malloc_state(A)         do_check_malloc_state (A)
```

이 함수들은 라이브러리 구현 과정에서의 코딩 실수 등을 검증하기 위해 존재하는 여러 assertion으로 이루어져 있다. 이는 중요한 검증 과정이 아니므로 다른 함수 내부에 등장할 경우 별도의 설명 없이 넘어가도록 하겠다.