#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <cmath>

static const int MAX_SIZE = 100000000;
static const int MAX_ORDER = 10;
static const int BLOCK_SIZE = 128;
static const int MAX_ORDER_SIZE = 128 * 1024;

struct MallocMetadata
{
    size_t size;
    bool is_free;
    MallocMetadata *next;
    MallocMetadata *prev;
};

static const int METADATA_SIZE = sizeof(MallocMetadata);

class SysStats
{
public:
    MallocMetadata *list;
    MallocMetadata *free_list[11];
    size_t num_free_blocks;
    size_t num_free_bytes;
    size_t num_allocated_blocks;
    size_t num_allocated_bytes;
    void *start_addr;
    SysStats() : list(nullptr), num_free_blocks(0), num_free_bytes(0), num_allocated_blocks(0), num_allocated_bytes(0),
                 start_addr(NULL)
    {
        for (int i = 0; i < 11; i++)
        {
            free_list[i] = nullptr;
        }
    }
    int _find_cell(size_t size);
    void _insert(void *toMerge, MallocMetadata *metadata);
    MallocMetadata *_divide_blocks(int desired, int current);
    void *_merge_blocks(void *toMerge, size_t size = 0);
};

SysStats stats = SysStats();

void *smalloc(size_t size)
{
    MallocMetadata *last = nullptr;
    if (stats.list == nullptr)
    {
        stats.start_addr = sbrk(0);
        void *section = sbrk(((32 * MAX_ORDER_SIZE) - (uintptr_t)stats.start_addr % (32 * MAX_ORDER_SIZE)) + (32 * MAX_ORDER_SIZE));
        if (section == (void *)(-1))
        {
            return NULL;
        }
        section = (char *)section + ((32 * MAX_ORDER_SIZE) - (uintptr_t)stats.start_addr % (32 * MAX_ORDER_SIZE));
        for (int i = 0; i < 32; i++)
        {
            MallocMetadata *data = (MallocMetadata *)((char *)section + i * (MAX_ORDER_SIZE));
            *data = {MAX_ORDER_SIZE, true, nullptr, last};
            if (data->prev == nullptr)
            {
                stats.list = data;
                stats.free_list[MAX_ORDER] = data;
            }
            else
            {
                data->prev->next = data;
            }
            last = data;
        }
        stats.num_free_blocks = 32;
        stats.num_allocated_blocks = 32;
        stats.num_allocated_bytes += 32 * MAX_ORDER_SIZE - 32 * (METADATA_SIZE);
        stats.num_free_bytes = 32 * MAX_ORDER_SIZE - 32 * (METADATA_SIZE);
    }
    if (size == 0 || size > MAX_SIZE)
    {
        return NULL;
    }
    if (size > (MAX_ORDER_SIZE - METADATA_SIZE))
    {
        void *section = mmap(NULL, size + METADATA_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        MallocMetadata *data = (MallocMetadata *)((char *)section);
        *data = {size, false, nullptr, nullptr};
        stats.num_allocated_blocks++;
        stats.num_allocated_bytes += size;
        return (char *)data + METADATA_SIZE;
    }

    // find cell that the size needed is closest to in size
    int cell = stats._find_cell(size);
    // send the cell to helper function which will divide blocks until have one to return
    MallocMetadata *addr = stats._divide_blocks(cell, cell);
    if (addr == NULL)
    {
        return NULL;
    }
    // remove from list in desired cell & update stats
    addr->is_free = false;
    stats.num_free_blocks--;
    stats.num_free_bytes -= (addr->size - METADATA_SIZE);
    stats.free_list[cell] = addr->next;
    if (addr->next != nullptr)
    {
        addr->next->prev = nullptr;
    }
    addr->prev = nullptr;
    addr->next = nullptr;
    return (char *)addr + METADATA_SIZE;
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
    if (p == NULL)
    {
        return;
    }
    MallocMetadata *metadata = (MallocMetadata *)((char *)p - METADATA_SIZE);
    if (metadata->size > (MAX_ORDER_SIZE) && !metadata->is_free)
    {
        stats.num_allocated_bytes -= metadata->size;
        stats.num_allocated_blocks--;
        metadata->is_free = true;
        munmap(metadata, metadata->size);
        return;
    }
    if (metadata->is_free)
    {
        return;
    }
    metadata->is_free = true;
    stats.num_free_blocks++;
    stats.num_free_bytes += metadata->size - METADATA_SIZE;
    stats._merge_blocks(p);
}

void *srealloc(void *oldp, size_t size)
{
    if (size == 0 || size > MAX_SIZE)
    {
        return NULL;
    }
    if (oldp == NULL)
    {
        return smalloc(size);
    }
    MallocMetadata *metadata = (MallocMetadata *)((char *)oldp - METADATA_SIZE);
    if (metadata->size >= size)
    {
        return oldp;
    }
    size_t calculated_size = metadata->size;
    void *runner = oldp;
    while (calculated_size < size + METADATA_SIZE)
    {
        MallocMetadata *runnerData = (MallocMetadata *)((char *)runner - METADATA_SIZE);
        void *buddy = (void *)((reinterpret_cast<uintptr_t>(runner) - METADATA_SIZE) ^ runnerData->size);
        MallocMetadata *buddyData = (MallocMetadata *)buddy;
        if (!buddyData->is_free || buddyData->size != metadata->size)
        {
            break;
        }
        calculated_size += buddyData->size;
        runner = std::min((char *)buddy, (char *)runner);
    }
    if (calculated_size >= size + METADATA_SIZE)
    {
        metadata->is_free = true;
        stats.num_free_bytes += metadata->size - METADATA_SIZE;
        void *addr = stats._merge_blocks(oldp, size + METADATA_SIZE);
        MallocMetadata *addrMeta = (MallocMetadata *)((char *)addr - METADATA_SIZE);
        addrMeta->is_free = false;
        stats.num_free_bytes -= (addrMeta->size - METADATA_SIZE);
        return addr;
    }
    void *status = smalloc(size);
    if (status == NULL)
    {
        return NULL;
    }
    memmove(status, oldp, metadata->size);
    sfree(oldp);
    return status;
}

int SysStats::_find_cell(size_t size)
{
    size_t tmpSize = size + METADATA_SIZE;
    return std::ceil(std::log2((double)tmpSize / 128));
}

void SysStats::_insert(void *toMerge, MallocMetadata *metadata)
{
    int cell = _find_cell(metadata->size - METADATA_SIZE);
    MallocMetadata *addr = stats.free_list[cell];
    if (addr == nullptr)
    {
        stats.free_list[cell] = metadata;
        return;
    }
    MallocMetadata *tmp = addr;
    // find largest address that is still smaller than toMerge so can be put in in size order
    while (tmp != nullptr)
    {
        if ((char *)tmp < (char *)toMerge)
        {
            addr = tmp;
        }
        else
        {
            break;
        }
        tmp = tmp->next;
    }
    MallocMetadata *addrData = (MallocMetadata *)addr;
    metadata->next = addrData->next;
    addrData->next = metadata;
    metadata->prev = addr;
    if (metadata->next != nullptr)
    {
        metadata->next->prev = metadata;
    }
}

MallocMetadata *SysStats::_divide_blocks(int desired, int current)
{
    if (current > MAX_ORDER)
    {
        return NULL;
    }
    MallocMetadata *stat;
    if (stats.free_list[current] == nullptr)
    {
        stat = _divide_blocks(desired, current + 1);
    }
    if (stats.free_list[current] == nullptr && stat == NULL)
    {
        return NULL;
    }
    if (stats.free_list[desired] != nullptr)
    {
        return stats.free_list[desired];
    }
    MallocMetadata *toSplit = stats.free_list[current];
    stats.free_list[current] = toSplit->next;
    if (toSplit->next != nullptr)
    {
        toSplit->next->prev = nullptr;
    }
    toSplit->size /= 2;
    MallocMetadata *secondBlock = (MallocMetadata *)((char *)toSplit + toSplit->size); // oi
    *secondBlock = {toSplit->size, true, nullptr, toSplit};
    toSplit->next = secondBlock;
    stats.free_list[current - 1] = toSplit;
    stats.num_free_blocks++;
    stats.num_allocated_blocks++;
    stats.num_allocated_bytes -= METADATA_SIZE;
    stats.num_free_bytes -= METADATA_SIZE;
    return toSplit;
}

void *SysStats::_merge_blocks(void *toMerge, size_t size)
{
    MallocMetadata *metadata = (MallocMetadata *)((char *)toMerge - METADATA_SIZE);
    if (metadata->size == MAX_ORDER_SIZE)
    {
        _insert(toMerge, metadata);
        return toMerge;
    }
    if (size != 0 && metadata->size >= size)
    {
        return toMerge;
    }
    void *buddy = (void *)((reinterpret_cast<uintptr_t>(toMerge) - METADATA_SIZE) ^ metadata->size);
    MallocMetadata *buddyData = (MallocMetadata *)buddy;
    if (!buddyData->is_free || buddyData->size != metadata->size)
    {
        _insert(toMerge, metadata);
        return NULL;
    }
    // if it was the last in the list
    int cell = _find_cell(metadata->size - METADATA_SIZE);
    if (stats.free_list[cell] == buddyData)
    {
        stats.free_list[cell] = buddyData->next;
    }
    if (buddyData->next != nullptr)
    {
        buddyData->next->prev = buddyData->prev;
    }
    if (buddyData->prev != nullptr)
    {
        buddyData->prev->next = buddyData->next;
    }
    buddyData->prev = nullptr;
    buddyData->next = nullptr;
    void *min = std::min((char *)toMerge, (char *)buddy + METADATA_SIZE);
    buddyData->size *= 2;
    metadata->size *= 2;
    stats.num_allocated_blocks--;
    stats.num_allocated_bytes += METADATA_SIZE;
    stats.num_free_blocks--;
    stats.num_free_bytes += METADATA_SIZE;
    return _merge_blocks(min, size);
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
    return stats.num_allocated_blocks * METADATA_SIZE;
}

size_t _size_meta_data()
{
    return METADATA_SIZE;
}