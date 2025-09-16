#include "userprog/syscall.h"
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "lib/kernel/stdio.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
static void sys_exit(struct intr_frame *f);
static void sys_write(struct intr_frame *f);
static void sys_create(struct intr_frame *f);
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

/* 유저 포인터 검증 실패를 즉시 종료로 처리해야 커널이 안전하며 테스트 요구사항을 만족한다.
 * => exit_bad_user(): 해당 프로세스만 깔끔하게 종료시키는 함수 */
// __attribute__((noreturn)): 이 함수는 절대 리턴하지 않는다고 컴파일러에 선언
static __attribute__((noreturn)) void
exit_bad_user(void)
{
	struct thread *t = thread_current();
	t->exit_status = -1; // exit(-1)
	thread_exit();		 // process_exit() 경로로 빠져 로그 1줄만 출력 후 돌아오지 않음

	// 위 호출이 절대 리턴하지 않는 것을 컴파일러에 확실히 알리는 힌트. 최적화/경고 억제에 쓰이며, 실제로 여기에 도달하면 정의되지 않은 동작으로 여겨짐
	__builtin_unreachable();
}

// uaddr에서 바이트 하나를 안전하게 읽기
static inline uint8_t
safe_read_u8(const void *uaddr)
{
	// NULL이거나 커널 영역 주소(>= KERN_BASE)면 바로 해당 프로세스 종료
	// is_user_vaddr는 주어진 가상주소가 유저 영역인지 판별
	if (uaddr == NULL || !is_user_vaddr(uaddr))
	{
		exit_bad_user();
	}

	// 현재 스레드의 최상위 페이지 테이블(PML4)를 통해 uaddr가 매핑된 물리 프레임을 찾고,
	// 그 프레임을 가리키는 커널 가상주소를 얻음. (매핑이 없으면 NULL)
	void *kaddr = pml4_get_page(thread_current()->pml4, uaddr);
	if (kaddr == NULL)
	{
		exit_bad_user();
	}
	// 검증 끝난 커널 가상주소로부터 1바이트 안전 읽기
	// 이걸 문자 단위 루프에서 쓰면, 문자열이 페이지 경계를 넘어도 각 바이트마다 독립적으로 검증되어 안전하게 동작한다.
	return *(const uint8_t *)kaddr;
}

// 반환: 커널 힙에 새로 할당된 NUL-종료 문자열 (caller가 free)
// too_long: 원본이 maxlen을 초과(= maxlen 내에 NUL 없음)했는지 신호
char *
copy_in_string_k(const char *ustr, size_t maxlen, bool *too_long)
{
	if (ustr == NULL)
	{
		exit_bad_user();
	}

	char *buf = malloc(maxlen + 1); // +1 for NUL
	ASSERT(buf != NULL);

	size_t i = 0;
	bool found_nul = false;

	// 최대 maxlen 바이트까지만 시도.
	while (i < maxlen)
	{
		// 매 루프에서 safe_read_u8(ustr + i)로 바이트 단위 검증+복사. (페이지 경계 안전)
		uint8_t ch = safe_read_u8(ustr + i);

		// 유저 문자열이 여기서 끝나면 found_nul=true로 표시하고 커널 버퍼에도 '\0' 기록.
		if (ch == '\0')
		{
			found_nul = true;
			buf[i] = '\0';
			break;
		}
		buf[i++] = (char)ch;
	}

	/* NUL을 못 만났다 = 원본 문자열이 maxlen 초과.
	 * 이건 “잘못된 포인터”가 아니라 정책 위반(과길이) 이므로 프로세스 kill 금지.
	 * 상위(예: sys_create)에서 false를 리턴하도록 신호만 올린다.
	 * 반면 잘못된 포인터/커널 영역/미매핑은 앞서 safe_read_u8()에서 즉시 종료 처리.
	 * 두 경우를 확실히 분리해야 한다! */
	if (!found_nul)
	{
		buf[i] = '\0'; // 안전상 트렁케이트
		if (too_long)
			*too_long = true; // 길이 초과 신호 (프로세스 kill 아님!)
	}
	else
	{
		if (too_long)
			*too_long = false;
	}
	return buf;
}

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
	NULL,		// SYS_HALT
	sys_exit,	// SYS_EXIT
	NULL,		// SYS_FORK
	NULL,		// SYS_EXEC
	NULL,		// SYS_WAIT
	sys_create, // SYS_CREATE
	NULL,		// SYS_REMOVE
	NULL,	   // SYS_OPEN
	NULL,		// SYS_FILESIZE
	NULL,		// SYS_READ
	sys_write,	// SYS_WRITE
	NULL,		// SYS_SEEK
	NULL,		// SYS_TELL
	NULL,		// SYS_CLOSE
};

static void sys_exit(struct intr_frame *f)
{
	int status = (int)f->R.rdi;
	struct thread *curr = thread_current();
	curr->exit_status = status;
	thread_exit();
}

/*
 * 시스템 콜 번호와 추가 인자들은 syscall 명령어를 호출하기 전에
 * 일반적인 방식으로 레지스터에 저장되어야 하지만, 두 가지 예외가 있다.
 * 1. %rax에는 시스템 콜 번호가 저장
 * 2. 네 번째 인자는 %rcx가 아니라 %r10에 저장
 * 따라서 시스템 콜 핸들러인 syscall_handler()가 제어권을 넘겨받으면, 시스템 콜 번호는 rax에 있고,
 * 인자들은 %rdi, %rsi, %rdx, %r10, %r8, %r9 순서로 전달됨 (6개 이상 부터는 스택에 저장)
 */
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

static void sys_create(struct intr_frame *f)
{
	const char *file_u = (const char *)f->R.rdi;
	unsigned size = (unsigned)f->R.rsi;

	bool too_long = false;
	char *name_k = copy_in_string_k(file_u, NAME_MAX, &too_long);

	if (too_long)
	{
		f->R.rax = false;
	}
	else if (name_k[0] == '\0')
	{
		f->R.rax = false;
	}
	else
	{
		f->R.rax = filesys_create(name_k, size);
	}

	free(name_k);
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
	// 시스템 콜 번호
	uint64_t n = f->R.rax;

	// n이 테이블 크기보다 크거나 같으면 존재하지 않는 시스템 콜 번호라는 뜻
	// 시스템 콜 번호가 범위 밖이거나, 해당 번호에 등록된 핸들러가 없으면 sys_badcall을 호출
	if (n >= (sizeof(syscall_tbl) / sizeof(syscall_tbl[0])) || syscall_tbl[n] == NULL)
	{
		sys_badcall(f);
		return;
	}
	syscall_tbl[n](f);
}