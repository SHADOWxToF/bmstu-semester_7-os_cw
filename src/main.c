#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/path.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/signal.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#include "help.h"
#include "list.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#define HAVE_PROC_OPS
#endif

#ifdef HAVE_PROC_OPS
static struct proc_ops myops;
static struct proc_ops help_ops;
static struct proc_ops command_ops;
static struct proc_ops report_ops;
#else
static struct file_operations myops;
static struct file_operations help_ops;
static struct file_operations command_ops;
static struct file_operations report_ops;
#endif

extern char *help_info;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ALEX");

#define BUFSIZE PAGE_SIZE
#define HELPBUF 100

# define MAIN_DIR "finder"
static struct proc_dir_entry *main_dir;
# define HELP_FILE "help"
static struct proc_dir_entry *help_file;
# define COMMAND_FILE "command"
static struct proc_dir_entry *command_file;
static proc_file_list_t proc_file_list;

# define MAX_LIBRARY_LEN 20

static struct dentry_library
{
    int len;
    struct dentry *array[MAX_LIBRARY_LEN];
} dentry_library = {.len = 0};

static char command_info[10 * MAX_FILE_LEN + 1];

static struct dentry *get_dentry_from_pathname(const char *pathname) 
{
    struct path path;
    int error = kern_path(pathname, LOOKUP_FOLLOW, &path);
    if (!error)
        return path.dentry;
    else
        return NULL;
}

static ssize_t report_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
    int i = 0;
    while (i < dentry_library.len && strcmp(dentry_library.array[i]->d_name.name, file->f_path.dentry->d_parent->d_name.name))
        ++i;
    struct dentry *dentry = dentry_library.array[i];
    if (!dentry)
        sprintf(command_info, "Что-то пошло не так\n");
    else
    {
        char kbuf[10 * MAX_FILE_LEN + 1];
        if (copy_from_user(kbuf, ubuf, count))
        {
            sprintf(command_info, "Не удалось скопировать данные из пользовательского режима\n");
            return -EFAULT;
        }
        kbuf[count - 1] = 0;
        
        long sig;
        int res = kstrtol(kbuf, 10, &sig);
        if (res)
        {
            sprintf(command_info, "Введены некорректные данные\n");
            return res;
        }
        struct task_struct *task = &init_task;
        do
        {
            struct files_struct *files = task->files;
            struct fdtable *fdt = files->fdt;
            if (fdt && files)
            {
                int signalize = 0;
                for (int i = 0; !res && i < files->next_fd; ++i)
                {
                    struct file *f = (fdt->fd)[i];
                    if (f->f_path.dentry == dentry)
                    {
                        signalize = 1;
                    }
                }
                if (signalize)
                    res = send_sig_info(sig, 1, task);
            }
        }
        while (!res && (task = next_task(task)) != &init_task);
    }
    sprintf(command_info, "Команда выполнена успешно\n");
    return count;
}

static ssize_t report_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos)
{
    if (*ppos > 0)
        return 0;

    int len = 0;
    char message[20 * MAX_FILE_LEN + 1];

    int i = 0;
    while (i < dentry_library.len && strcmp(dentry_library.array[i]->d_name.name, file->f_path.dentry->d_parent->d_name.name))
        ++i;
    struct dentry *dentry = dentry_library.array[i];
    if (!dentry)
    {
        sprintf(command_info, "Что-то пошло не так\n");
        len += sprintf(message, "Что-то пошло не так\n");
    }
    else
    {
        sprintf(command_info, "Команда выполнена успешно\n");
        len += sprintf(message + len, "%7s %7s %7s %7s %7s %7s\n", "PPID", "PID", "FD", "PRIO", "STATE", "COMMAND");
        struct task_struct *task = &init_task;
        do
        {
            struct files_struct *files = task->files;
            struct fdtable *fdt = files->fdt;
            if (fdt && files)
            {
                for (int i = 0; i < files->next_fd; ++i)
                {
                    struct file *f = (fdt->fd)[i];
                    if (f->f_path.dentry == dentry)
                    {
                        len += sprintf(message + len, "%7d %7d %7d %7d %7d %s\n", task->parent->pid, task->pid, i, task->prio, task->__state, task->comm);
                    }
                }
            }
        }
        while ((task = next_task(task)) != &init_task);
    }
    if (copy_to_user(ubuf, message, len))
        return -EFAULT;
    *ppos += len;
    return len;
}

static ssize_t command_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos) 
{
    if (dentry_library.len == MAX_LIBRARY_LEN)
    {
        sprintf(command_info, "Невозможно отслеживать более %d файлов\n", MAX_LIBRARY_LEN);
        return count;
    }
    char kbuf[10 * MAX_FILE_LEN + 1];
    if (copy_from_user(kbuf, ubuf, count))
        return -EFAULT;
    kbuf[count - 1] = 0;
    struct dentry *dentry = get_dentry_from_pathname(kbuf);
    struct proc_dir_entry *dir;
    struct proc_dir_entry *report_file;
    int status = 0;
    if (!dentry)
        sprintf(command_info, "Данного пути не существует в системе");
    else if (!(dir = proc_mkdir(dentry->d_name.name, main_dir)))
        status = -ENOMEM;
    else if (!(proc_symlink("symlink", dir, kbuf)))
    {
        remove_proc_entry(dentry->d_name.name, main_dir);
        status = -ENOMEM;
    }
    else if (!(report_file = proc_create("report", 0646, dir, &report_ops)))
    {
        remove_proc_entry("symlink", dir);
        remove_proc_entry(dentry->d_name.name, main_dir);
        status = -ENOMEM;
    }
    else if (status)
        sprintf(command_info, "Ошибка при создании директорий\n");
    else
    {
        proc_file_list_append(&proc_file_list, dentry->d_name.name, main_dir);
        proc_file_list_append(&proc_file_list, "symlink", dir);
        proc_file_list_append(&proc_file_list, "report", dir);
        dentry_library.array[(dentry_library.len)++] = dentry;
        sprintf(command_info, "Путь распознан. Создана папка %s, proc_dir_entry=%p\n", dentry->d_name.name, (void *) report_file);
    }
    return count;
}

static ssize_t command_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
    if (*ppos > 0)
        return 0;
    
    int len;
    if (command_info[0])
    {
        len = strlen(command_info);
        if (copy_to_user(ubuf, command_info, len))
            return -EFAULT;
    }
    else
    {
        len = strlen(help_info);
        if (copy_to_user(ubuf, help_info, len))
            return -EFAULT;
    }
    *ppos += len;
    return len;
}

static ssize_t help_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
    if (*ppos > 0)
        return 0;
    
    int len = strlen(help_info);
    if (copy_to_user(ubuf, help_info, len))
        return -EFAULT;
    *ppos += len;
	return len;
}

static int myopen(struct inode *inode, struct file *file)
{
    struct hlist_node *list = (inode->i_dentry).first;
    struct dentry *d = list_entry(list, struct dentry, d_u.d_alias);
    printk(KERN_INFO "file %s is opened", d->d_name.name);
    return 0;
}

static int myrelease(struct inode *inode, struct file *file)
{
    struct hlist_node *list = (inode->i_dentry).first;
    struct dentry *d = list_entry(list, struct dentry, d_u.d_alias);
    printk(KERN_INFO "file %s is released", d->d_name.name);
    return 0;
}


#ifdef HAVE_PROC_OPS
static struct proc_ops help_ops = 
{
	.proc_read = help_read,
    .proc_open = myopen,
    .proc_release = myrelease,
};
static struct proc_ops command_ops = 
{
    .proc_read = command_read,
	.proc_write = command_write,
    .proc_open = myopen,
    .proc_release = myrelease,
};
static struct proc_ops report_ops = 
{
    .proc_read = report_read,
	.proc_write = report_write,
    .proc_open = myopen,
    .proc_release = myrelease,
};
#else
static struct file_operations help_ops =
{
    .read = help_read,
    .open = myopen,
    .release = myrelease,
};
static struct file_operations command_ops =
{
    .read = command_read,
    .write = command_write,
    .open = myopen,
    .release = myrelease,
};
static struct file_operations report_ops =
{
    .read = report_read,
    .write = report_write,
    .open = myopen,
    .release = myrelease,
};
#endif

static int __init myinit(void)
{   
    command_info[0] = 0;
    if (alloc_proc_file_list(&proc_file_list, 10, 2))
    {
        return -ENOMEM;
    }
    if (!(main_dir = proc_mkdir(MAIN_DIR, NULL)))
    {
        free_proc_file_list(&proc_file_list);
        return -ENOMEM;
    }
    if (!(help_file = proc_create(HELP_FILE, 0444, main_dir, &help_ops)))
    {
        free_proc_file_list(&proc_file_list);
        remove_proc_entry(MAIN_DIR, NULL);
        return -ENOMEM;
    }
    if (!(command_file = proc_create(COMMAND_FILE, 0646, main_dir, &command_ops)))
    {
        free_proc_file_list(&proc_file_list);
        remove_proc_entry(HELP_FILE, NULL);
        remove_proc_entry(MAIN_DIR, NULL);
        return -ENOMEM;
    }
    proc_file_list_append(&proc_file_list, MAIN_DIR, NULL);
    proc_file_list_append(&proc_file_list, HELP_FILE, main_dir);
    proc_file_list_append(&proc_file_list, COMMAND_FILE, main_dir);
    return 0;
}

static void __exit myexit(void)
{
    proc_file_t *pfile;
    while ((pfile = proc_file_list_pop(&proc_file_list)))
    { 
        remove_proc_entry(pfile->name, pfile->parent);
        kfree(pfile->name);
        kfree(pfile);
    }
    free_proc_file_list(&proc_file_list);
}

module_init(myinit);
module_exit(myexit);

/*
рисунок сокращать до рис.
разбитые листинги с одинаковым названием
не использовать слово "поле"
пункт 4.2 ИССЛЕДОВАНИЕ работы программы
*/