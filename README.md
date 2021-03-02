# glibc 2.23 malloc() 분석

현재진행중.

## __libc_malloc

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

## _int_malloc : init

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

0x10부터 32바이트가 할당되고, 청크의 size에는 0x31이 적혀있다. (청크 크기가 항상 8의 배수기 때문에 가장 아래쪽 세 개의 비트는 다른 정보들을 나타내는데 사용된다. 따라서 실제 크기는 0x30이라고 생각하면 된다.)

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

## _int_malloc: fastbin

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
    }
```



## Background

**atomic_forced_read**

```c
#ifndef atomic_forced_read
# define atomic_forced_read(x) \
  ({ __typeof (x) __x; __asm ("" : "=r" (__x) : "0" (x)); __x; })
#endif
```

https://stackoverflow.com/questions/58082597/what-is-the-purpose-of-glibcs-atomic-forced-read-function

##### **__builtin_expect**

```c
/* Tell the compiler when a conditional or integer expression is
   almost always true or almost always false.  */
#ifndef HAVE_BUILTIN_EXPECT
# define __builtin_expect(expr, val) (expr)
#endif
```

컴파일러에게 주어진 expr의 값이 참과 거짓 중 어느 한 쪽이 많이 등장함을 알려줌으로써 조건문의 분기 예측 최적화에 도움을 준다. 자주 발생하지 않는 예외 등을 처리할 때 사용하면 프로그램 성능이 향상될 것이다.

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

**alignment**

C 언어의 기본 데이터 타입은 모두 자신의 크기와 동일한 정렬 제한을 가진다. 정렬 제한이란 데이터가 메모리에 저장될 때 해당 메모리의 주소에 대한 제약 사항을 말하는 것이다.