#include <unistd.h>
#include <stdio.h>

static const int MAX_SIZE = 100000000;

struct MallocMetadata
{
    size_t size;
    bool is_free;
    MallocMetadata *next;
    MallocMetadata *prev;
};

class SysStats {
public: 
    MallocMetadata *list;
    size_t num_free_blocks;
    size_t num_free_bytes;
    size_t num_allocated_blocks;
    size_t num_allocated_bytes;
    SysStats() : list(nullptr), num_free_blocks(0), num_free_bytes(0), num_allocated_blocks(0), num_allocated_bytes(0){}
};

SysStats stats = SysStats();

void *smalloc(size_t size)
{
    if (size == 0 || size > MAX_SIZE)
    {
        return NULL;
    }
    MallocMetadata *last = NULL;
    if (stats.list != nullptr)
    {
        MallocMetadata *tmp = stats.list;
        while (tmp != nullptr)
        {
            if (tmp->is_free && tmp->size >= size)
            {
                tmp->is_free = false;
                stats.num_free_blocks--;
                stats.num_free_bytes -= tmp->size;
                return tmp + sizeof(MallocMetadata);
            }
            last = tmp;
            tmp = tmp->next;
        }
    }
    void *section = sbrk(size + sizeof(MallocMetadata));
    if (section == (void *)(-1))
    {
        return NULL;
    }
    stats.num_allocated_blocks++;
    stats.num_allocated_bytes += size;
    MallocMetadata *data = (MallocMetadata *)section;
    *data = {size, false, nullptr, last};
    if (data->prev == nullptr)
    {
        stats.list = data;
    }
    return (char*)section + sizeof(MallocMetadata);
}

void *scalloc(size_t num, size_t size)
{
    void *section = smalloc(num * size);
    if (section == NULL)
    {
        return NULL;
    }
    memset(section, 0, num * size);
    return section;
}

void sfree(void *p)
{
    if (p == NULL) {
        return;
    }
    MallocMetadata* metadata = (MallocMetadata*)((char*)p - sizeof(MallocMetadata));
    if (metadata->is_free) {
        return;
    }
    metadata->is_free = true;
    stats.num_free_blocks++;
    stats.num_free_bytes += metadata->size;
}

void *srealloc(void *oldp, size_t size)
{
    if (size == 0 || size > MAX_SIZE) {
        return NULL;
    }
    if (oldp == NULL) {
        return smalloc(size);
    }
    MallocMetadata* metadata = (MallocMetadata*)((char*)oldp - sizeof(MallocMetadata));
    if (metadata->size >= size) {
        return oldp;
    }
    void* status = smalloc(size);
    if (status == NULL) {
        return NULL;
    }
    memmove(status, oldp, metadata->size);
    sfree(oldp);
    return status;
}

size_t _num_free_blocks()
{
    return stats.num_free_blocks;
}

size_t _num_free_bytes()
{
    return stats.num_free_bytes;
}

size_t _num_allocated_blocks()
{
    return stats.num_allocated_blocks;
}

size_t _num_allocated_bytes()
{
    return stats.num_allocated_bytes;
}

size_t _num_meta_data_bytes()
{
    return stats.num_allocated_blocks*sizeof(MallocMetadata);
}

size_t _size_meta_data()
{
    return sizeof(MallocMetadata);
}