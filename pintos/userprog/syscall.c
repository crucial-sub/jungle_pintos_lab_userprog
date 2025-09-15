#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "lib/kernel/stdio.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
static void sys_exit(struct intr_frame *f);
static void sys_write(struct intr_frame *f);
static void sys_badcall(struct intr_frame *f);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* syscall_handler lookup 테이블 방식 구현
 * syscall-nr.h 파일에 정의된 시스템 콜 번호에 대응하는 함수 포인터들을 배열로 미리 마련해둠
 * 시스템 콜이 발생하면 f->R.rax 값을 인덱스로 삼아 해당하는 함수를 바로 호출 */
typedef void (*syscall_handler_t)(struct intr_frame *f); // 함수 포인터 형 재선언

static const syscall_handler_t syscall_tbl[] = {
	NULL,	   // SYS_HALT
	sys_exit,  // SYS_EXIT
	NULL,	   // SYS_FORK
	NULL,	   // SYS_EXEC
	NULL,	   // SYS_WAIT
	NULL,	   // SYS_CREATE
	NULL,	   // SYS_REMOVE
	NULL,	   // SYS_OPEN
	NULL,	   // SYS_FILESIZE
	NULL,	   // SYS_READ
	sys_write, // SYS_WRITE
	NULL,	   // SYS_SEEK
	NULL,	   // SYS_TELL
	NULL,	   // SYS_CLOSE
};

static void sys_exit(struct intr_frame *f)
{
	int status = (int)f->R.rdi;
	struct thread *curr = thread_current();
	curr->exit_status = status;
	thread_exit();
}

static void sys_write(struct intr_frame *f)
{
	int fd = (int)f->R.rdi;
	const char *buf = (const char *)f->R.rsi;
	size_t size = (size_t)f->R.rdx;

	if (fd == 1)
	{
		putbuf(buf, size);
		f->R.rax = size;
	}
	else
	{
		f->R.rax = (uint64_t)-1;
	}
}

static void sys_badcall(struct intr_frame *f)
{
	f->R.rdi = (uint64_t)-1;
	sys_exit(f);
}

/* The main system call interface
 * Pintos에서는 사용자 프로그램이 시스템 콜을 할 때 syscall을 사용
 * 시스템 콜 번호와 추가 인자들은 syscall 명령어를 호출하기 전에 일반적인 방식으로 레지스터에 저장되어야 하지만, 두 가지 예외가 있다.
 * 1. %rax에는 시스템 콜 번호가 저장
 * 2. 네 번째 인자는 %rcx가 아니라 %r10에 저장
 * 따라서 시스템 콜 핸들러인 syscall_handler()가 제어권을 넘겨받으면, 시스템 콜 번호는 rax에 있고,
 * 인자들은 %rdi, %rsi, %rdx, %r10, %r8, %r9 순서로 전달됨 (6개 이상 부터는 스택에 저장) */
void syscall_handler(struct intr_frame *f)
{
	uint64_t n = f->R.rax;

	if (n >= (sizeof(syscall_tbl) / sizeof(syscall_tbl[0])) || syscall_tbl[n] == NULL)
	{
		sys_badcall(f);
		return;
	}
	syscall_tbl[n](f);
}