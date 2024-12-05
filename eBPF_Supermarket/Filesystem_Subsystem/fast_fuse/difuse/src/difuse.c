#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>

/*相关数据结构*/

#define FILE_TYPE 1
#define DIRECTORY_TYPE 2
#define MAX_INODES 1000  //最大 inode 数量
#define HASH_SIZE 1024
#define CHUNK_SIZE 4096 // 数据块的大小

uint32_t next_ino = 1;

struct dfs_data
{
    char *data;
    size_t size;
    struct dfs_data *next;
};

static struct dfs_data *allocate_data_block()
{
    struct dfs_data *new_data = (struct dfs_data *)malloc(sizeof(struct dfs_data));
    new_data->data = (char *)malloc(CHUNK_SIZE);
    new_data->next = NULL;
    return new_data;
}

struct dfs_inode
{
    uint32_t ino;                       // inode编号
    int size;                           // 文件大小
    int dir_cnt;                        // 目录项数量
    struct dfs_data *data_pointer;      // 数据块指针
    time_t atime;                       // 最后访问时间
    time_t mtime;                       // 最后修改时间
    struct dfs_inode *prev;
    struct dfs_inode *next;
};


struct dfs_dentry
{
    char fname[255];
    int ftype;
    struct dfs_dentry *parent;
    struct dfs_dentry *brother;
    struct dfs_dentry *child;
    struct dfs_inode *inode;            //指向对应的inode
    struct dfs_dentry *prev;            //LRU 链表前驱指针
    struct dfs_dentry *next;            //LRU 链表后继指针
};

struct dfs_dentry *root;                    //根节点
struct dfs_dentry *lru_head = NULL;         //LRU 链表头
struct dfs_dentry *lru_tail = NULL;         //LRU 链表尾
struct dfs_dentry *hash_table[HASH_SIZE];   //哈希表

// inode回收队列
struct dfs_inode *inode_recycle_list = NULL;  // inode 回收队列头

/*缓存管理*/

static unsigned int hash(const char *path)
{
    unsigned int hash = 0;
    while (*path)
    {
        hash = (hash << 5) + *path++;
    }
    return hash % HASH_SIZE;
}

static void lru_remove(struct dfs_dentry *dentry)
{
    if (dentry->prev)
    {
        dentry->prev->next = dentry->next;
    }
    else
    {
        lru_head = dentry->next;
    }
    if (dentry->next)
    {
        dentry->next->prev = dentry->prev;
    }
    else
    {
        lru_tail = dentry->prev;
    }
}

static void lru_insert(struct dfs_dentry *dentry)
{
    dentry->next = lru_head;
    dentry->prev = NULL;
    if (lru_head)
    {
        lru_head->prev = dentry;
    }
    lru_head = dentry;
    if (!lru_tail)
    {
        lru_tail = dentry;
    }
}

static void lru_access(struct dfs_dentry *dentry)
{
    lru_remove(dentry);
    lru_insert(dentry);
}

static void lru_evict()
{
    if (lru_tail)
    {
        struct dfs_dentry *evict = lru_tail;
        lru_remove(evict);
        unsigned int index = hash(evict->fname);
        hash_table[index] = NULL;
        free(evict->inode);
        free(evict);
    }
}

/* 回收 inode 相关函数 */
static void add_to_inode_recycle_list(struct dfs_inode *inode)
{
    inode->next = inode_recycle_list;
    inode_recycle_list = inode;
}

static struct dfs_inode *get_recycled_inode()
{
    if (inode_recycle_list)
    {
        struct dfs_inode *inode = inode_recycle_list;
        inode_recycle_list = inode->next;
        inode->next = NULL;  // 复用 inode 时，清除 next 指针
        return inode;
    }
    return NULL;
}

/*过程函数*/
static struct dfs_inode *new_inode(int size, int dir_cnt)
{
    struct dfs_inode *inode = get_recycled_inode();  // 优先从回收队列中获取 inode
    if (!inode)
    {
        inode = (struct dfs_inode *)malloc(sizeof(struct dfs_inode));
        inode->ino = next_ino++;
    }

    inode->size = size;
    inode->dir_cnt = dir_cnt;
    inode->data_pointer = NULL;
    inode->prev = NULL;
    inode->next = NULL;
    return inode;
}

static struct dfs_dentry *new_dentry(char *fname, int ftype, struct dfs_dentry *parent, struct dfs_inode *inode)
{
    struct dfs_dentry *dentry = (struct dfs_dentry *)malloc(sizeof(struct dfs_dentry));
    strcpy(dentry->fname, fname);
    dentry->inode = inode;
    dentry->brother = NULL;
    dentry->parent = parent;
    dentry->child = NULL;
    dentry->ftype = ftype;
    dentry->prev = NULL;
    dentry->next = NULL;
    return dentry;
}

void add_child_dentry(struct dfs_dentry *parent, struct dfs_dentry *child)
{
    child->brother = parent->child;
    parent->child = child;
}

static int remove_child_dentry(struct dfs_dentry *parent, struct dfs_dentry *child)
{
    struct dfs_dentry *prev_child = NULL;
    struct dfs_dentry *cur_child = parent->child;

    while (cur_child != NULL && cur_child != child)
    {
        prev_child = cur_child;
        cur_child = cur_child->brother;
    }
    if (cur_child == NULL)
        return 0;

    if (prev_child == NULL)
        parent->child = cur_child->brother;
    else prev_child->brother = cur_child->brother;
    return 1;
}

struct dfs_dentry *traverse_path(struct dfs_dentry *start_dentry, const char *path, int ftype, int create)
{
    struct dfs_dentry *dentry = start_dentry;
    char *path_copy = strdup(path);
    char *token = strtok(path_copy, "/");

    while (token != NULL)
    {
        struct dfs_dentry *child = dentry->child;
        while (child != NULL && strcmp(child->fname, token) != 0)
        {
            child = child->brother;
        }

        if (child == NULL)
        {
            if (create)
            {
                struct dfs_inode *new_inodes = new_inode(0, 0); // 创建新的 inode
                child = new_dentry(token, ftype, dentry, new_inodes); // 创建新的目录项
                add_child_dentry(dentry, child); // 将新目录项添加到父目录项的子目录列表中
            }
            else
            {
                free(path_copy);
                return NULL;
            }
        }

        dentry = child;
        token = strtok(NULL, "/");
    }

    free(path_copy);
    return dentry;
}

struct dfs_dentry *look_up(struct dfs_dentry *dentrys, const char *path)
{
    return traverse_path(dentrys, path, 0, 0);
}

struct dfs_dentry *lookup_or_create_dentry(const char *path, struct dfs_dentry *start_dentry, int ftype)
{
    unsigned int index = hash(path);
    struct dfs_dentry *dentry = hash_table[index];

    if (dentry)
    {
        lru_access(dentry);
        return dentry;
    }

    dentry = traverse_path(start_dentry, path, ftype, 1);
    if (dentry)
    {
        lru_insert(dentry);
        hash_table[index] = dentry;
        if (next_ino > MAX_INODES)
        {
            lru_evict();
        }
    }

    return dentry;
}

static void free_inode(struct dfs_inode *inode)
{
    struct dfs_data *data_block = inode->data_pointer;
    while (data_block)
    {
        struct dfs_data *next = data_block->next;
        free(data_block->data);
        free(data_block);
        data_block = next;
    }
    add_to_inode_recycle_list(inode);  // 将inode添加到回收队列
}


/*功能函数*/
static int di_unlink(const char *path)
{
    struct dfs_dentry *dentry = look_up(root, path);

    if (dentry == NULL)
        return -ENOENT;
    if (dentry->ftype != FILE_TYPE)
        return -EISDIR;

    if (remove_child_dentry(dentry->parent, dentry))
    {
        lru_remove(dentry);
        unsigned int index = hash(dentry->fname);
        hash_table[index] = NULL;
        free_inode(dentry->inode);  // 释放inode添加到回收队列
        free(dentry);
        return 0;
    }
    return -ENOENT;
}

static int di_rmdir(const char *path)
{
    struct dfs_dentry *dentry = look_up(root, path);

    if (dentry == NULL)
        return -ENOENT;
    if (dentry->ftype != DIRECTORY_TYPE)
        return -ENOTDIR;
    if (dentry->child != NULL)
        return -ENOTEMPTY;

    // 移除子目录项
    if (remove_child_dentry(dentry->parent, dentry))
    {
        lru_remove(dentry);
        unsigned int index = hash(dentry->fname);
        hash_table[index] = NULL;
        free(dentry->inode);
        free(dentry);
        return 0;
    }
    return -ENOENT;
}

static int di_utimens(const char *path, const struct timespec ts[2], struct fuse_file_info *fi)
{
    (void)fi;
    struct dfs_dentry *dentry = look_up(root, path);
    if (dentry == NULL)
    {
        return -ENOENT;
    }

    // 设置文件的时间戳
    dentry->inode->atime = ts[0].tv_sec;  // 访问时间
    dentry->inode->mtime = ts[1].tv_sec;  // 修改时间

    return 0;
}


static int di_mkdir(const char *path, mode_t mode)
{
    (void)mode;
    struct dfs_dentry *dentry = lookup_or_create_dentry(path, root, DIRECTORY_TYPE);
    if (dentry == NULL)
    {
        return -ENOENT;
    }

    return 0;
}

static int di_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    (void)mode;
    (void)fi;
    struct dfs_dentry *existing = look_up(root, path);
    if (existing != NULL)
    {
        return -EEXIST;  // 文件已存在，返回错误
    }
    struct dfs_dentry *dentry = lookup_or_create_dentry(path, root, FILE_TYPE);
    if (dentry == NULL)
    {
        return -ENOENT;
    }

    return 0;
}

static int di_getattr(const char *path, struct stat *di_stat, struct fuse_file_info *fi)
{
    (void)fi;
    memset(di_stat, 0, sizeof(struct stat));

    struct dfs_dentry *dentry = look_up(root, path);
    if (dentry == NULL)
        return -ENOENT;

    if (dentry->ftype == DIRECTORY_TYPE)
    {
        di_stat->st_mode = S_IFDIR | 0755;
        di_stat->st_nlink = 2;
    }
    else if (dentry->ftype == FILE_TYPE)
    {
        di_stat->st_mode = S_IFREG | 0644;
        di_stat->st_nlink = 1;
        di_stat->st_size = dentry->inode->size;
    }

    di_stat->st_atime = dentry->inode->atime;  // 最后访问时间
    di_stat->st_mtime = dentry->inode->mtime;  // 最后修改时间

    return 0;
}


/*遍历目录项*/
static int di_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
    (void)fi;
    (void)offset;
    (void)flags;
    struct dfs_dentry *dentry = look_up(root, path);

    if (dentry == NULL)
        return -ENOENT;

    if (dentry->ftype != DIRECTORY_TYPE)
        return -ENOTDIR;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    struct dfs_dentry *child = dentry->child;
    while (child != NULL)
    {
        filler(buf, child->fname, NULL, 0, 0);
        child = child->brother;
    }

    return 0;
}

static int di_open(const char *path, struct fuse_file_info *fi)
{
    struct dfs_dentry *dentry = look_up(root, path);

    if (dentry == NULL)
        return -ENOENT;

    if (dentry->ftype != FILE_TYPE)
        return -EISDIR;

    return 0;
}

static int di_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    struct dfs_dentry *dentry = look_up(root, path);

    if (dentry == NULL)
        return -ENOENT;

    if (dentry->ftype != FILE_TYPE)
        return -EISDIR;

    struct dfs_inode *inode = dentry->inode;
    size_t file_size = inode->size;

    if (offset >= file_size)
        return 0;

    if (offset + size > file_size)
        size = file_size - offset;

    size_t bytes_read = 0;
    struct dfs_data *data_block = inode->data_pointer;

    // 遍历数据块，处理偏移和读取
    while (data_block != NULL && bytes_read < size)
    {
        if (offset >= CHUNK_SIZE)
        {
            offset -= CHUNK_SIZE;
            data_block = data_block->next;
            continue;
        }

        size_t to_read = CHUNK_SIZE - offset;
        if (to_read > size - bytes_read)
            to_read = size - bytes_read;

        memcpy(buf + bytes_read, data_block->data + offset, to_read);
        bytes_read += to_read;
        offset = 0;  // 只有第一个块需要处理 offset，之后的块直接从头开始

        data_block = data_block->next;
    }

    return bytes_read;
}


static int di_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    (void)fi;
    struct dfs_dentry *dentry = look_up(root, path);

    if (dentry == NULL) return -ENOENT;
    if (dentry->ftype != FILE_TYPE) return -EISDIR;

    struct dfs_inode *inode = dentry->inode;
    struct dfs_data *data_block = inode->data_pointer;

    if (data_block == NULL)
    {
        data_block = allocate_data_block();
        inode->data_pointer = data_block;
    }

    size_t bytes_written = 0;
    size_t total_offset = offset;

    while (data_block != NULL && total_offset >= CHUNK_SIZE)
    {
        total_offset -= CHUNK_SIZE;
        if (data_block->next == NULL)
        {
            data_block->next = allocate_data_block();
        }
        data_block = data_block->next;
    }

    while (bytes_written < size)
    {
        size_t space_in_block = CHUNK_SIZE - total_offset;
        size_t to_write = size - bytes_written;

        if (to_write > space_in_block) to_write = space_in_block;

        memcpy(data_block->data + total_offset, buf + bytes_written, to_write);

        total_offset = 0;
        bytes_written += to_write;
        data_block->size += to_write;

        if (bytes_written < size && data_block->next == NULL)
        {
            data_block->next = allocate_data_block();
        }
        data_block = data_block->next;
    }

    if (offset + bytes_written > inode->size)
    {
        inode->size = offset + bytes_written;
    }

    return bytes_written;
}


static void *di_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
    (void)conn;

    // 创建并初始化根目录的 inode 和 dentry
    struct dfs_inode *root_inode = new_inode(0, 0);
    root = new_dentry("/", DIRECTORY_TYPE, NULL, root_inode);

    return 0;
}

static struct fuse_operations difs_ops = {
    .init = di_init,
    .readdir = di_readdir,
    .getattr = di_getattr,
    .open = di_open,
    .read = di_read,
    .write = di_write,
    .mkdir = di_mkdir,
    .create = di_create,
    .utimens = di_utimens,
    .unlink = di_unlink,
    .rmdir = di_rmdir,
};

int main(int argc, char *argv[])
{
    return fuse_main(argc, argv, &difs_ops, NULL);
}