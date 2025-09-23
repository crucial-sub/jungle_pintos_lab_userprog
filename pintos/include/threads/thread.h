#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#ifdef VM
#include "vm/vm.h"
#endif

/* States in a thread's life cycle. */
enum thread_status
{
	THREAD_RUNNING, /* Running thread. */
	THREAD_READY,	/* Not running but ready to run. */
	THREAD_BLOCKED, /* Waiting for an event to trigger. */
	THREAD_DYING	/* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) - 1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0	   /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63	   /* Highest priority. */

struct file;
#define FD_MAX 32

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread
{
	/* Owned by thread.c. */
	tid_t tid;				   /* Thread identifier. */
	enum thread_status status; /* Thread state. */
	char name[16];			   /* Name (for debugging purposes). */
	int priority;			   /* Priority. */
	/* Shared between thread.c and synch.c. */
	struct list_elem elem; /* List element. */

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4; /* Page map level 4 */
	int exit_status;

	/* 프로세스 별 FD테이블 추가 */
	struct file *fd_table[FD_MAX]; // 열린 파일들의 포인터 저장
	int fd_next;				   // 다음에 할당할 FD 번호

	/* 부모-자식 관계 정립 및 자식 프로세스 추적 */
	struct thread *parent;			   // 자신의 부모 프로세스를 가리키는 포인터
	struct list children;			   // 자신의 자식 프로세스 목록을 관리하기 위한 리스트
	struct child_status *child_status; // 부모-자식 관계를 위한 구조체

	/* exec 파일 관리 */
	struct file *exec_file;
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf; /* Information for switching */
	unsigned magic;		  /* Detects stack overflow. */

	/* ----- Alarm Clock additions ----- */
	int64_t wakeup_tick; /* 이 스레드를 깨워야 할 절대 tick (timer_ticks() 기준) */

	/* 원래 우선순위(사용자 설정값) */
	int base_priority;

	/* 나에게 우선순위를 기부한 스레드들의 리스트 */
	struct list donations; /* elements: donor->donation_elem */

	/* 내가 남에게 기부자로 들어갈 때 사용할 리스트 노드 (단일 용도) */
	struct list_elem donation_elem;

	/* 지금 대기 중인 락 (없으면 NULL). 중첩 기부 전파용 */
	struct lock *wait_on_lock;
};

struct child_status
{
	tid_t tid;					 // 자식 tid
	int exit_status;			 // 자식 exit status
	int refer_cnt;				 // 참조 카운트(부모 1 + 자식 1 = 초기값 2)
	struct semaphore sema;		 // 자식 종료 시 sema_up으로 부모를 깨움, 부모는 여기서 down
	struct list_elem child_elem; // 부모의 children 리스트에 들어갈 노드
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

void do_iret(struct intr_frame *tf);

bool thread_cmp_priority(const struct list_elem *a,
						 const struct list_elem *b,
						 void *aux UNUSED);

void thread_refresh_priority(struct thread *t);
void thread_remove_donations_for_lock(struct thread *t, struct lock *lock);
void thread_resort_ready_member(struct thread *t);

#endif /* threads/thread.h */
