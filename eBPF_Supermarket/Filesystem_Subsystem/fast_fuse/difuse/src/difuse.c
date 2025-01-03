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
// 预读相关常量定义
#define MIN_PREFETCH_SIZE 1    // 最小预读块数
#define MAX_PREFETCH_SIZE 8    // 最大预读块数
#define SEQUENTIAL_THRESHOLD 3 

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
    if (!new_data)
    {
        return NULL;
    }

    new_data->data = (char *)malloc(CHUNK_SIZE);
    if (!new_data->data)
    {
        free(new_data);
        return NULL;
    }

    memset(new_data->data, 0, CHUNK_SIZE);  // 初始化数据块
    new_data->size = 0;
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
    struct access_pattern
    {
        off_t last_offset;              // 上次访问的偏移量
        int sequential_count;           // 连续顺序访问计数
        int prefetch_size;             // 当前预读窗口大小
        time_t last_access_time;       // 上次访问时间
    } access;                          // 访问模式跟踪
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

/*预读机制*/

// 初始化访问模式跟踪
static void init_access_pattern(struct access_pattern *pattern)
{
    pattern->last_offset = -1;
    pattern->sequential_count = 0;
    pattern->prefetch_size = MIN_PREFETCH_SIZE;
    pattern->last_access_time = time(NULL);
}

// 更新访问模式统计
static void update_access_pattern(struct access_pattern *pattern, off_t current_offset)
{
    time_t current_time = time(NULL);

    // 检查是否为顺序访问
    if (pattern->last_offset != -1 &&
        current_offset == pattern->last_offset + CHUNK_SIZE)
    {
        pattern->sequential_count++;

        // 如果连续顺序访问次数达到阈值，增加预读窗口
        if (pattern->sequential_count >= SEQUENTIAL_THRESHOLD &&
            pattern->prefetch_size < MAX_PREFETCH_SIZE)
        {
            pattern->prefetch_size *= 2;
            if (pattern->prefetch_size > MAX_PREFETCH_SIZE)
            {
                pattern->prefetch_size = MAX_PREFETCH_SIZE;
            }
        }
    }
    else
    {
        // 非顺序访问，重置统计
        pattern->sequential_count = 0;
        pattern->prefetch_size = MIN_PREFETCH_SIZE;
    }

    // 如果距离上次访问时间过长，重置预读窗口
    if (current_time - pattern->last_access_time > 5)
    { // 5秒超时
        pattern->prefetch_size = MIN_PREFETCH_SIZE;
        pattern->sequential_count = 0;
    }

    pattern->last_offset = current_offset;
    pattern->last_access_time = current_time;
}

// 增强的预读机制
static void prefetch_data_blocks(struct dfs_inode *inode, off_t offset)
{
    if (offset >= inode->size)
    {
        return;
    }

    // 更新访问模式
    update_access_pattern(&inode->access, offset);

    struct dfs_data *data_block = inode->data_pointer;
    off_t current_offset = 0;

    // 定位到当前偏移量对应的块
    while (data_block != NULL && current_offset + CHUNK_SIZE <= offset)
    {
        current_offset += CHUNK_SIZE;
        data_block = data_block->next;
    }

    // 预读后续多个块
    int blocks_to_prefetch = inode->access.prefetch_size;
    while (blocks_to_prefetch > 0 && data_block != NULL)
    {
        // 如果当前块没有后续块且未达到文件末尾，创建新块
        if (data_block->next == NULL && current_offset + CHUNK_SIZE < inode->size)
        {
            data_block->next = allocate_data_block();
            if (data_block->next == NULL)
            {
                // 内存分配失败，停止预读
                break;
            }
        }
        data_block = data_block->next;
        current_offset += CHUNK_SIZE;
        blocks_to_prefetch--;
    }
}


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
        if (!inode)
        {
            return NULL;  // 内存分配失败
        }
        inode->ino = next_ino++;
    }

    inode->size = size;
    inode->dir_cnt = dir_cnt;
    inode->data_pointer = NULL;
    inode->prev = NULL;
    inode->next = NULL;
    inode->atime = time(NULL);
    inode->mtime = time(NULL);

    // 初始化访问模式跟踪
    init_access_pattern(&inode->access);

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
    (void)fi;
    struct dfs_dentry *dentry = look_up(root, path);

    if (dentry == NULL)
    {
        return -ENOENT;
    }
    if (dentry->ftype != FILE_TYPE)
    {
        return -EISDIR;
    }

    struct dfs_inode *inode = dentry->inode;
    size_t file_size = inode->size;

    if (offset >= file_size)
    {
        return 0;
    }
    if (offset + size > file_size)
    {
        size = file_size - offset;
    }

    // 使用增强的预读机制
    prefetch_data_blocks(inode, offset);

    size_t bytes_read = 0;
    struct dfs_data *data_block = inode->data_pointer;
    off_t current_offset = 0;

    // 找到起始数据块和块内偏移
    while (data_block != NULL && offset >= CHUNK_SIZE)
    {
        offset -= CHUNK_SIZE;
        data_block = data_block->next;
        current_offset += CHUNK_SIZE;
    }

    // 读取数据
    while (data_block != NULL && bytes_read < size)
    {
        size_t block_read_size = CHUNK_SIZE - offset;
        if (block_read_size > (size - bytes_read))
        {
            block_read_size = size - bytes_read;
        }

        memcpy(buf + bytes_read, data_block->data + offset, block_read_size);
        bytes_read += block_read_size;
        offset = 0;  // 后续块从头开始读取

        data_block = data_block->next;
        current_offset += CHUNK_SIZE;
    }

    // 更新访问时间
    inode->atime = time(NULL);

    return bytes_read;
}

static int di_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    (void)fi;
    struct dfs_dentry *dentry = look_up(root, path);

    if (dentry == NULL)
    {
        return -ENOENT;
    }
    if (dentry->ftype != FILE_TYPE)
    {
        return -EISDIR;
    }

    struct dfs_inode *inode = dentry->inode;

    // 确保有第一个数据块
    if (inode->data_pointer == NULL)
    {
        inode->data_pointer = allocate_data_block();
        if (!inode->data_pointer)
        {
            return -ENOMEM;
        }
    }

    struct dfs_data *data_block = inode->data_pointer;
    size_t bytes_written = 0;
    off_t current_offset = 0;

    // 定位到正确的数据块
    while (data_block != NULL && offset >= CHUNK_SIZE)
    {
        offset -= CHUNK_SIZE;
        if (data_block->next == NULL)
        {
            data_block->next = allocate_data_block();
            if (!data_block->next)
            {
                return bytes_written > 0 ? bytes_written : -ENOMEM;
            }
        }
        data_block = data_block->next;
        current_offset += CHUNK_SIZE;
    }

    // 写入数据
    while (bytes_written < size)
    {
        size_t block_write_size = CHUNK_SIZE - offset;
        if (block_write_size > (size - bytes_written))
        {
            block_write_size = size - bytes_written;
        }

        memcpy(data_block->data + offset, buf + bytes_written, block_write_size);
        if (offset + block_write_size > data_block->size)
        {
            data_block->size = offset + block_write_size;
        }

        bytes_written += block_write_size;
        offset = 0;  // 后续块从头开始写入

        if (bytes_written < size)
        {
            if (data_block->next == NULL)
            {
                data_block->next = allocate_data_block();
                if (!data_block->next)
                {
                    break;  // 内存分配失败，返回已写入的字节数
                }
            }
            data_block = data_block->next;
            current_offset += CHUNK_SIZE;
        }
    }

    // 更新文件大小
    off_t new_size = offset + bytes_written;
    if (new_size > inode->size)
    {
        inode->size = new_size;
    }

    // 更新修改时间
    inode->mtime = time(NULL);

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