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
#include "lib/user/syscall.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
static void sys_halt(struct intr_frame *f);
static void sys_wait(struct intr_frame *f);
static void sys_exit(struct intr_frame *f);
static void sys_exec(struct intr_frame *f);
static tid_t sys_fork(struct intr_frame *f);
static void sys_write(struct intr_frame *f);
static void sys_create(struct intr_frame *f);
static void sys_remove(struct intr_frame *f);
static void sys_open(struct intr_frame *f);
static void sys_close(struct intr_frame *f);
static void sys_read(struct intr_frame *f);
static void sys_filesize(struct intr_frame *f);
static void sys_seek(struct intr_frame *f);
static void sys_tell(struct intr_frame *f);
static void sys_badcall(struct intr_frame *f);
static void *get_validated_kaddr(const void *uaddr);
static void check_valid_buffer(const void *buf, size_t size);
static inline uint8_t safe_read_u8(const void *uaddr);
static void safe_write_u8(const void *uaddr, uint8_t v);
static void safe_copy_to_user(const char *user_dest, const char *kernel_src, size_t size);
char *copy_in_string_k(const char *ustr, size_t maxlen, bool *too_long);

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
__attribute__((noreturn)) void
exit_bad_user(void)
{
	struct thread *t = thread_current();
	t->exit_status = -1; // exit(-1)
	thread_exit();		 // process_exit() 경로로 빠져 로그 1줄만 출력 후 돌아오지 않음

	// 위 호출이 절대 리턴하지 않는 것을 컴파일러에 확실히 알리는 힌트. 최적화/경고 억제에 쓰이며, 실제로 여기에 도달하면 정의되지 않은 동작으로 여겨짐
	__builtin_unreachable();
}

/*
 * 주어진 유저 주소 uaddr의 유효성을 검사하고,
 * 접근 가능한 커널 가상 주소를 반환한다.
 * 유효하지 않은 주소일 경우, 프로세스를 종료시킨다.
 */
static void *get_validated_kaddr(const void *uaddr)
{
	// 1. NULL 포인터이거나 커널 영역 주소이면 안 됨.
	if (uaddr == NULL || !is_user_vaddr(uaddr))
	{
		exit_bad_user();
	}

	// 2. 페이지 테이블을 확인하여 실제 물리 메모리에 매핑되어 있는지 확인.
	void *kaddr = pml4_get_page(thread_current()->pml4, uaddr);
	if (kaddr == NULL)
	{
		// 매핑되지 않은 주소라면 접근 불가.
		exit_bad_user();
	}

	// 3. 모든 검증을 통과한 안전한 커널 주소를 반환.
	return kaddr;
}

/*
 * 주어진 유저 버퍼(buf, size)의 모든 페이지가 유효한지 검사한다.
 * 유효하지 않은 페이지가 발견되면, get_validated_kaddr 내부에서
 * 프로세스를 종료시키므로 이 함수는 반환하지 않는다.
 */
static void check_valid_buffer(const void *buf, size_t size)
{
	// 1. 버퍼의 시작 주소 자체는 get_validated_kaddr가 검사해 줄 것이므로
	//    여기서는 size가 0인 경우만 간단히 처리하고 넘어간다.
	if (size == 0)
	{
		return;
	}

	uintptr_t start = (uintptr_t)buf;
	uintptr_t end = start + size - 1;

	// 2. 버퍼가 걸쳐 있는 각 페이지에 대해 검사를 수행한다.
	uintptr_t current_addr;
	for (current_addr = start & ~(PGSIZE - 1);
		 current_addr < end;
		 current_addr += PGSIZE)
	{
		// get_validated_kaddr는 uaddr의 유효성을 검사하고,
		// 실패 시 알아서 exit_bad_user()를 호출한다.
		// 우리는 그냥 호출해주기만 하면 된다.
		(void)get_validated_kaddr((const void *)current_addr);
	}
}

// uaddr에서 바이트 하나를 안전하게 읽기
static inline uint8_t
safe_read_u8(const void *uaddr)
{
	const uint8_t *kaddr = get_validated_kaddr(uaddr);
	return *kaddr;
}

// uaddr에 바이트 하나를 안전하게 쓰기
static void safe_write_u8(const void *uaddr, uint8_t value)
{
	uint8_t *kaddr = get_validated_kaddr(uaddr);
	*kaddr = value;
}

static void safe_copy_to_user(const char *user_dest, const char *kernel_src, size_t size)
{
	// 한 바이트씩 순회하며 복사
	for (int i = 0; i < size; i++)
	{
		// 1. 현재 복사할 소스 바이트를 가져온다 (커널 메모리이므로 직접 접근 가능)
		char byte_to_copy = kernel_src[i];
		// 2. 현재 데이터를 써야 할 목적지 주소 계산
		const char *current_user_addr = user_dest + i;
		// 3. 해당 목적지 주소에 한 바이트를 '안전하게' 쓴다.
		//    이 작업은 별도의 헬퍼 함수로 만드는 것이 깔끔하다.
		safe_write_u8(current_user_addr, byte_to_copy);
	}
}

// 유저 주소(user_src)에서 커널 버퍼(kernel_dest)로 안전 복사
static void safe_copy_from_user(void *kernel_dest, const char *user_src, size_t size)
{
	uint8_t *kd = (uint8_t *)kernel_dest;
	const uint8_t *uu = (const uint8_t *)user_src;
	for (size_t i = 0; i < size; i++)
	{
		// 유저 공간에서 안전하게 1바이트를 읽어와서 커널 버퍼에 '직접' 저장
		kd[i] = safe_read_u8(uu + i);
	}
}

// 반환: 커널 힙에 새로 할당된 NUL-종료 문자열 (caller가 free)
// too_long: 원본이 maxlen을 초과(= maxlen 내에 NUL 없음)했는지 신호
char *copy_in_string_k(const char *ustr, size_t maxlen, bool *too_long)
{
	char *kbuf = malloc(maxlen + 1); // +1 for NUL
	if (kbuf == NULL)
	{
		return NULL;
	}

	size_t i = 0;
	bool found_nul = false;

	// 최대 maxlen 바이트까지만 시도.
	for (i = 0; i < maxlen; i++)
	{
		// 매 루프에서 safe_read_u8(ustr + i)로 바이트 단위 검증+복사. (페이지 경계 안전)
		uint8_t ch = safe_read_u8(ustr + i);

		kbuf[i] = ch;
		// '\0'을 찾으면 found_nul을 true로 바꾸고 루프 종료
		if (ch == '\0')
		{
			found_nul = true;
			break;
		}
	}

	// NUL 문자를 못 찾았을 경우를 대비해, 문자열을 강제로 null-terminated로 만들어준다.
	kbuf[i] = '\0';

	if (too_long != NULL)
	{
		*too_long = !found_nul;
	}

	return kbuf;
}

/* fd 헬퍼 */
// fd테이블에서 빈 번호 찾아서 파일에 fd할당
int fd_allocate(struct file *f)
{
	struct thread *t = thread_current();
	int start = t->fd_next; // 다음 후보 시작점
	if (start < 2 || start >= FD_MAX)
	{
		start = 2;
	}

	/* 1) start..FD_MAX-1, 2) 2..start-1 순서로 한 바퀴만 돈다 */
	for (int pass = 0; pass < 2; pass++)
	{
		int i = (pass == 0 ? start : 2);
		int end = (pass == 0 ? FD_MAX : start);

		for (; i < end; i++)
		{
			if (t->fd_table[i] == NULL)
			{
				t->fd_table[i] = f;
				t->fd_next = (i + 1 < FD_MAX ? i + 1 : 2); // 다음 탐색 힌트
				return i;								   // FD = 인덱스
			}
		}
	}
	return -1; // fd테이블이 가득 참
}

// fd->file* 변환: read/write/close 같은 시스템콜은 FD를 받아오니까, 역으로 file* 를 찾아야 함
struct file *fd_get(int fd)
{
	struct thread *t = thread_current();
	if (fd < 0 || fd >= FD_MAX)
		return NULL;
	return t->fd_table[fd];
}

// fd 해제: fd_table에 번호 반납하고 실제 파일도 close
bool fd_close(int fd)
{
	struct thread *t = thread_current();
	if (fd < 2 || fd >= FD_MAX || t->fd_table[fd] == NULL)
	{
		return false; // 닫을 수 없는 fd
	}
	file_close(t->fd_table[fd]);
	t->fd_table[fd] = NULL;
	return true;
}

void fd_close_all()
{
	struct thread *t = thread_current();
	for (int i = 2; i < FD_MAX; i++)
	{
		fd_close(i);
	}
	t->fd_next = 2;
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
	sys_halt,	  // SYS_HALT
	sys_exit,	  // SYS_EXIT
	sys_fork,	  // SYS_FORK
	sys_exec,	  // SYS_EXEC
	sys_wait,	  // SYS_WAIT
	sys_create,	  // SYS_CREATE
	sys_remove,	  // SYS_REMOVE
	sys_open,	  // SYS_OPEN
	sys_filesize, // SYS_FILESIZE
	sys_read,	  // SYS_READ
	sys_write,	  // SYS_WRITE
	sys_seek,	  // SYS_SEEK
	sys_tell,	  // SYS_TELL
	sys_close,	  // SYS_CLOSE
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
 * 인자들은 %rdi, %rsi, %rdx, %r10, %r8, %r9 순서로 전달됨 (6개 이상 부터는 스택에 저장)`
 */
static void sys_halt(struct intr_frame *f)
{
	power_off();
}

static void sys_badcall(struct intr_frame *f)
{
	f->R.rdi = (uint64_t)-1;
	sys_exit(f);
}

static void sys_wait(struct intr_frame *f)
{
	pid_t pid = f->R.rdi;
	f->R.rax = process_wait(pid);
}

static void sys_exec(struct intr_frame *f)
{
	struct thread *curr = thread_current();
	const char *cmd_line_u = (const char *)f->R.rdi;

	bool too_long = false;
	char *cmd_line_k = copy_in_string_k(cmd_line_u, PGSIZE, &too_long);
	if (cmd_line_k == NULL || too_long)
	{
		if (cmd_line_k)
		{
			free(cmd_line_k); // 누수 방지
		}
		curr->exit_status = -1;
		thread_exit(); // exec 실패 규약
	}

	char *fn_copy = palloc_get_page(0);
	if (fn_copy == NULL)
	{
		free(cmd_line_k);
		curr->exit_status = -1;
		thread_exit(); // 커널 OOM도 실패로 종료
	}

	strlcpy(fn_copy, cmd_line_k, PGSIZE);
	free(cmd_line_k);

	int res = process_exec(fn_copy);
	// 성공 시 process_exec는 복귀하지 않는다.
	// 복귀했다 = 실패: 임시 페이지 회수 후 -1로 종료
	curr->exit_status = -1;
	thread_exit();
}

static tid_t
sys_fork(struct intr_frame *f)
{
	const char *uname = (const char *)f->R.rdi;
	bool too_long = false;
	char *kname = copy_in_string_k(uname, PGSIZE, &too_long);

	if (kname == NULL)
	{ // 커널 OOM: 실패를 값으로
		f->R.rax = TID_ERROR;
		return;
	}
	if (too_long)
	{ // 이름이 지나치게 길면 실패 처리(커널은 안전)
		free(kname);
		f->R.rax = TID_ERROR;
		return;
	}

	tid_t tid = process_fork(kname, f); // process_fork 내부에서 자식 성공/실패 확정 후 sema_up
	free(kname);						// 누수 방지
	f->R.rax = tid;						// 성공: pid, 실패: TID_ERROR
}

static void sys_create(struct intr_frame *f)
{
	const char *file_u = (const char *)f->R.rdi;
	unsigned size = (unsigned)f->R.rsi;
	bool too_long = false;

	char *name_k = copy_in_string_k(file_u, NAME_MAX, &too_long);

	if (name_k == NULL || too_long || name_k[0] == '\0')
	{
		if (name_k)
			free(name_k);
		f->R.rax = false;
		return;
	}
	f->R.rax = filesys_create(name_k, size);
	free(name_k);
}

static void sys_remove(struct intr_frame *f)
{
	const char *file_u = (const char *)f->R.rdi;
	bool too_long = false;
	char *name_k = copy_in_string_k(file_u, NAME_MAX, &too_long);

	if (name_k == NULL || too_long || name_k[0] == '\0')
	{
		if (name_k)
			free(name_k);
		f->R.rax = false;
		return;
	}
	f->R.rax = filesys_remove(name_k);
	free(name_k);
}

static void sys_open(struct intr_frame *f)
{
	const char *file_u = (const char *)f->R.rdi;
	bool too_long = false;
	char *name_k = copy_in_string_k(file_u, NAME_MAX, &too_long);

	if (name_k == NULL || too_long || name_k[0] == '\0')
	{
		if (name_k)
		{
			free(name_k);
		}
		f->R.rax = -1;
		return;
	}

	struct file *file = filesys_open(name_k);
	if (file == NULL)
	{
		free(name_k);
		f->R.rax = -1;
		return;
	}

	int fd = fd_allocate(file);
	if (fd < 0)
	{
		/* 여기서 반드시 되돌리기! */
		file_close(file);
		free(name_k);
		f->R.rax = -1;
		return;
	}

	free(name_k);
	f->R.rax = fd;
}

static void sys_close(struct intr_frame *f)
{
	int fd = (int)f->R.rdi;
	if (fd_close(fd))
	{
		f->R.rax = 0; // 성공
	}
	else
	{
		f->R.rax = -1; // 실패
	}
}

static void sys_read(struct intr_frame *f)
{
	int fd = (int)f->R.rdi;
	const char *buf = (const char *)f->R.rsi;
	size_t size = (size_t)f->R.rdx;

	check_valid_buffer(buf, size);

	if (size == 0)
	{
		f->R.rax = 0;
		return;
	}
	if (fd == 1) // stdout
	{
		f->R.rax = -1;
		return;
	}
	if (fd == 0)
	{
		f->R.rax = input_getc();
		return;
	}

	struct file *file = fd_get(fd);
	if (file == NULL) // read-bad-fd
	{
		f->R.rax = -1;
		return;
	}

	char *kbuf = malloc(size);
	if (kbuf == NULL)
	{
		f->R.rax = -1; // 메모리 부족
		return;
	}

	off_t bytes_read = file_read(file, kbuf, size);

	safe_copy_to_user(buf, kbuf, bytes_read);

	// 5. 자원 해제 및 결과 반환
	free(kbuf);
	f->R.rax = bytes_read;
}

static void sys_filesize(struct intr_frame *f)
{
	int fd = (int)f->R.rdi;
	struct file *file = fd_get(fd);
	if (file == NULL)
	{
		f->R.rax = -1;
		return;
	}
	f->R.rax = file_length(file);
}

static void sys_seek(struct intr_frame *f)
{
	int fd = (int)f->R.rdi;
	off_t position = (off_t)f->R.rsi;

	struct file *file = fd_get(fd);
	if (file == NULL)
	{
		f->R.rax = -1;
		return;
	}

	file_seek(file, position);

	f->R.rax = file_tell(file);
}

static void sys_tell(struct intr_frame *f)
{
	int fd = (int)f->R.rdi;
	struct file *file = fd_get(fd);
	if (file == NULL)
	{
		f->R.rax = -1;
		return;
	}
	f->R.rax = file_tell(file);
}

static void sys_write(struct intr_frame *f)
{
	int fd = (int)f->R.rdi;
	const char *ubuf = (const void *)f->R.rsi;
	size_t size = (size_t)f->R.rdx;
	if (size == 0)
	{
		f->R.rax = 0;
		return;
	}

	// 유저 버퍼 전체가 유효한지 페이지 단위로 검증
	check_valid_buffer(ubuf, size);

	if (fd == 0) // stdin에 write → 에러
	{
		f->R.rax = -1;
		return;
	}
	if (fd == 1) // stdout
	{
		// 콘솔로 바로 내보내기
		putbuf(ubuf, size);
		f->R.rax = size;
		return;
	}
	if (fd > 1) // 일반 파일에 쓰는 경우
	{
		struct file *file = fd_get(fd);
		if (file == NULL)
		{
			f->R.rax = -1;
			return;
		}

		// 1. 커널 버퍼 할당
		char *kbuf = malloc(size);
		if (kbuf == NULL)
		{
			f->R.rax = -1; // 메모리 부족
			return;
		}

		// 2. 유저 버퍼의 내용을 커널 버퍼로 안전하게 복사
		safe_copy_from_user(kbuf, ubuf, size);

		// 3. 커널 버퍼의 내용을 파일에 쓰기
		off_t bytes_written = file_write(file, kbuf, size);

		// 4. 자원 해제 및 결과 반환
		free(kbuf);
		f->R.rax = bytes_written;
	}
}

/* The main system call interface */
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