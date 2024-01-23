# ifndef LIST_H

# define LIST_H

#include <linux/slab.h>
#include <linux/string.h>

# define MAX_FILE_LEN 100

typedef struct proc_file_t
{
    const char *name;
    struct proc_dir_entry *parent;
} proc_file_t;

typedef struct proc_file_list_t
{
    int size;
    int len;
    proc_file_t *array;
    int k;
} proc_file_list_t;

int alloc_proc_file_list(proc_file_list_t *list, int size, int k);
int proc_file_list_append(proc_file_list_t *list, const char *name, struct proc_dir_entry *pdentry);
proc_file_t *proc_file_list_pop(proc_file_list_t *list);
void free_proc_file_list(proc_file_list_t *list);

# endif