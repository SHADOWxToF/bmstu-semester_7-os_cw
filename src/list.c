#include "list.h"

int alloc_proc_file_list(proc_file_list_t *list, int size, int k)
{
    list->array = kmalloc(size * sizeof(proc_file_t), GFP_KERNEL); // GFP_KERNEL - обычный запрос, который можно блокировать
    if (list->array)
    {
        list->k = k;
        list->size = size;
        list->len = 0;
        return 0;
    }
    return -1;
}

int proc_file_list_append(proc_file_list_t *list, const char *name, struct proc_dir_entry *pdentry)
{
    if (list->len == list->size)
    {
        proc_file_t *new_pointer = krealloc(list->array, list->size * list->k, GFP_KERNEL);
        if (!new_pointer)
            return -ENOMEM;
        list->array = new_pointer;
        list->size *= list->k;
    }
    char *new_name = kmalloc((MAX_FILE_LEN + 1) * sizeof(char), GFP_KERNEL);
    if (!new_name)
        return -ENOMEM;
    strcpy(new_name, name);
    list->array[list->len].name = new_name;
    list->array[list->len].parent = pdentry;
    ++(list->len);
    return 0;
}

proc_file_t *proc_file_list_pop(proc_file_list_t *list)
{
    if (!list->len)
        return NULL;
    proc_file_t *result = kmalloc(sizeof(proc_file_t), GFP_KERNEL);
    if (!result)
        return NULL;
    --(list->len);
    memcpy(result, list->array + list->len, sizeof(proc_file_t));
    return result;
}

void free_proc_file_list(proc_file_list_t *list)
{
    kfree(list->array);
    list->array = NULL;
}