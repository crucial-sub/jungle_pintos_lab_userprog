#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
void fd_close_all();
__attribute__((noreturn)) void
exit_bad_user(void);

#endif /* userprog/syscall.h */
