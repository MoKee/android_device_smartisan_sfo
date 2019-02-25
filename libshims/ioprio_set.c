#include <unistd.h>
#include <sys/syscall.h>

int ioprio_set(int which, int who, int ioprio)
{
    return syscall(SYS_ioprio_set, which, who, ioprio);
}
