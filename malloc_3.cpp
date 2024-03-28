#include <unistd.h>
#include <string.h>

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
        for (i = 0; i < 11; i++)
        {
            free_list[i] = nullptr;
        }
    }
    int _find_cell(size_t size);
    void _insert(void *toMerge, MallocMetadata *metadata);
    void *_divide_blocks(int desired, int current);
    void _merge_blocks(void *toMerge);
};

SysStats stats = SysStats();

void *smalloc(size_t size)
{
    if (size == 0 || size > MAX_SIZE)
    {
        return NULL;
    }
    MallocMetadata *last = nullptr;
    if (stats.list == nullptr)
    {
        stats.start_addr = sbrk(0);
        void *section = sbrk(32 * MAX_ORDER_SIZE);
        for (int i = 0; i < 32; i++)
        {
            MallocMetadata *data = (MallocMetadata *)((char *)section + i * (MAX_ORDER_SIZE));
            *data = {size, true, nullptr, last};
            if (data->prev == nullptr)
            {
                stats.list = data;
                stats.free_list[MAX_ORDER] = data;
            }
            else
            {
                last->next = data;
            }
            last = data;
        }
        stats.num_allocated_blocks = 32;
        stats.num_allocated_bytes = 32 * MAX_ORDER_SIZE - 32 * (METADATA_SIZE);
        stats.num_free_blocks = 32;
        stats.num_free_bytes = 32 * MAX_ORDER_SIZE - 32 * (METADATA_SIZE);
    }

    // find cell that the size needed is closest to in size
    int cell = _find_cell(size);
    // send the cell to helper function which will divide blocks until have one to return
    // helper function returns address
    void *addr = _divide_blocks(cell, cell);
    // remove from list in desired cell & update stats
    MallocMetadata *metadata = (MallocMetadata *)addr;
    metadata->is_free = false;
    stats.num_free_blocks--;
    stats.num_free_bytes -= (metadata->size - METADATA_SIZE);
    stats.free_list[cell] = metadata->next;
    if (metadata->next != nullptr)
    {
        metadata->next->prev = nullptr;
    }
    metadata->prev = nullptr;
    metadata->next = nullptr;
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
    if (metadata->is_free)
    {
        return;
    }
    metadata->is_free = true;
    stats.num_free_blocks++;
    stats.num_free_bytes += metadata->size - METADATA_SIZE;
    _merge_blocks(p);
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
    int cell = 0;
    size_t tmpSize = size + METADATA_SIZE;
    while (tmpSize > 128)
    {
        tmpSize /= 2;
        cell++;
    }
    return cell;
}

void SysStats::_insert(void *toMerge, MallocMetadata *metadata)
{
    int cell = _find_cell(metadata->size);
    void *addr = stats.free_list[cell];
    if (addr == nullptr)
    {
        stats.free_list[cell] = toMerge;
    }
    void *tmp = addr;
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

void *SysStats::_divide_blocks(int desired, int current)
{
    if (current > MAX_ORDER)
    {
        return NULL;
    }
    if (stats.free_list[current] == nullptr)
    {
        _divide_blocks(desired, current + 1);
    }
    if (stats.free_list[desired] != nullptr)
    {
        return stats.free_list[desired];
    }
    // split
    // remove first block in cell to be split
    // set the cell current to point to the next term in the list
    // divide the block size into two
    // create new metadata for the second block
    // change size of the first block's metadata
    // set the current -1 cell to point to the first of the two halved blocks
    // return address of first block in the list
    MallocMetadata *toSplit = stats.free_list[current];
    stats.free_list[current] = toSplit->next;
    if (toSplit->next != nullptr)
    {
        toSplit->next->prev = nullptr;
    }
    toSplit->size /= 2;
    MallocMetadata *secondBlock = (MallocMetadata *)((char *)toSplit + toSplit->size);
    *secondBlock = {toSplit->size, true, toSplit, nullptr};
    toSplit->next = secondBlock;
    stats.free_list[current - 1] = toSplit;
    stats.num_free_blocks++;
    stats.num_allocated_blocks++;
    stats.num_allocated_bytes -= METADATA_SIZE;
    stats.num_free_bytes -= METADATA_SIZE;
    return toSplit;
}

// Check this function!!
void SysStats::_merge_blocks(void *toMerge)
{
    MallocMetadata *metadata = (MallocMetadata *)((char *)toMerge - METADATA_SIZE);
    if (metadata->size == MAX_ORDER_SIZE)
    {
        _insert(toMerge, metadata);
        return;
    }
    void *buddy = (((char *)toMerge - (char *)stats.start_addr) ^ metadata->size) + (char *)stats.start_addr;
    MallocMetadata *buddyData = (MallocMetadata *)buddy;
    if (!buddyData->is_free || buddyData->size != metadata->size)
    {
        _insert(toMerge, metadata);
        return;
    }
    // merge
    // remove buddy block from cell
    // find which of two has lower address
    // keep its metadata only
    // update size field
    // fix linked list next/prev for merged node
    // update the pointers
    // update stats data
    // recursive call on the merged node
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
    void *min = toMerge;
    if ((char *)toMerge >= (char *)buddy)
    {
        min = buddy;
        buddyData->size *= 2;
    }
    else
    {
        metadata->size *= 2;
    }
    stats.num_allocated_blocks--;
    stats.num_allocated_bytes += METADATA_SIZE;
    stats.num_free_blocks--;
    stats.num_free_bytes += METADATA_SIZE;
    _merge_blocks(min);
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