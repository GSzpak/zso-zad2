#include <asm/uaccess.h>
#include <linux/bug.h>
#include <linux/cdev.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include "vintage2d.h"
#include "v2d_ioctl.h"


MODULE_LICENSE("GPL");


/*************************** Defines ***********************************/

#define MAX_NUM_OF_DEVICES                  256
#define DRIVER_NAME                         "vintage2d-pci"
#define DEVICE_CLASS_NAME                   "graphic"
#define MMIO_SIZE                           4096
#define MAX_WIDTH                           2048
#define MAX_HEIGHT                          2048
#define MIN_WIDTH                           1
#define MIN_HEIGHT                          1
/* Buffer size for SRC_POS / DST_POS / FILL_COLOR commands */
#define HIS_BUF_SIZE                        2
/* Size of buffer for commands */
#define COMMAND_BUF_SIZE                    65536
#define COMMAND_SIZE                        4
/* Last 4 bytes are reserved for JUMP command */
#define REAL_BUF_SIZE                       (COMMAND_BUF_SIZE - COMMAND_SIZE)
#define JUMP_TO(addr)                       ((0xfffffffc & addr) | VINTAGE2D_CMD_KIND_JUMP)
/* Flags sent to COUNTER for synchronization */
#define COUNTER_FLAG_0                      1
#define COUNTER_FLAG_1                      0
#define REQUIRED_POS_CMD_BITS_ZERO(cmd)     (((cmd) & (1 << 19 | 1 << 31)) == 0)
#define REQUIRED_FILL_COLOR_BITS_ZERO(cmd)  (((cmd) & 0xffff0000) == 0)
#define REQUIRED_DRAW_CMD_BITS_ZERO(cmd)    (((cmd) & (1 << 19 | 1 << 31)) == 0)
#define VINTAGE2D_PAGE_MASK                 (~(VINTAGE2D_PAGE_SIZE - 1))


/**************************** Typedefs *********************************/

typedef struct {
    void *cpu_addr;
    dma_addr_t dma_addr;
} vintage_mem_t;

typedef struct {
    vintage_mem_t page_table;
    vintage_mem_t *pages;
    unsigned long num_of_pages;
} canvas_page_info_t;

typedef struct {
    long prev_commands[HIS_BUF_SIZE];
    int ind;
} command_his_t;

typedef struct {
    vintage_mem_t buf;
    long *cpu_write_ptr;
    dma_addr_t dma_write_ptr;
} command_buf_t;

typedef struct pci_dev_info pci_dev_info_t;
typedef struct dev_context_info dev_context_info_t;

struct pci_dev_info {
    int device_number;
    int minor;
    dev_t dev_number;
    struct pci_dev *pci_dev;
    struct cdev *char_dev;
    void __iomem *iomem;
    command_buf_t command_buf;
    struct mutex mutex;
    dev_context_info_t *current_context;
    wait_queue_head_t wait_queue;
};

struct dev_context_info {
    pci_dev_info_t *pci_dev_info;
    int was_ioctl;
    canvas_page_info_t canvas_page_info;
    long canvas_height;
    long canvas_width;
    command_his_t command_his;
    struct mutex mutex;
};


/****************** Device / file operations declarations **************/

static int vintage_probe(struct pci_dev *, const struct pci_device_id *);
static void vintage_remove(struct pci_dev *);
ssize_t vintage_write(struct file *, const char __user *, size_t, loff_t *);
long vintage_ioctl(struct file *, unsigned int, unsigned long);
int vintage_mmap(struct file *, struct vm_area_struct *);
int vintage_open(struct inode *, struct file *);
int vintage_release(struct inode *, struct file *);
int vintage_fsync(struct file *, loff_t, loff_t, int);


/*********************** Global vaiables *******************************/

static struct pci_device_id pci_ids[] = {
    { PCI_DEVICE(VINTAGE2D_VENDOR_ID, VINTAGE2D_DEVICE_ID), },
    { 0, }
};
static struct pci_driver vintage_driver = {
    .name = DRIVER_NAME,
    .id_table = pci_ids,
    .probe = vintage_probe,
    .remove = vintage_remove,
};
static struct file_operations vintage_file_ops = {
    .owner = THIS_MODULE,
    .write = vintage_write,
    .unlocked_ioctl = vintage_ioctl,
    .compat_ioctl = vintage_ioctl,
    .mmap = vintage_mmap,
    .open = vintage_open,
    .release = vintage_release,
    .fsync = vintage_fsync
};
static dev_t dev_number;
static unsigned int major;
static pci_dev_info_t dev_info_array[MAX_NUM_OF_DEVICES];
static struct class *vintage_class;

MODULE_DEVICE_TABLE(pci, pci_ids);


/******************** Definitions ****************************/

// General device utils

void
send_to_dev(long val, pci_dev_info_t *dev_info, long reg)
{
    iowrite32(val, dev_info->iomem + reg);
}

unsigned int
read_from_dev(pci_dev_info_t *dev_info, long reg)
{
    return ioread32(dev_info->iomem + reg);
}

void
reset_device(pci_dev_info_t *dev_info)
{
    /* Reset device */
    send_to_dev(VINTAGE2D_RESET_DRAW | VINTAGE2D_RESET_FIFO | VINTAGE2D_RESET_TLB,
                dev_info, VINTAGE2D_RESET);
    /* Reset interrupts */
    send_to_dev(VINTAGE2D_INTR_NOTIFY | VINTAGE2D_INTR_INVALID_CMD |
                VINTAGE2D_INTR_PAGE_FAULT | VINTAGE2D_INTR_CANVAS_OVERFLOW |
                VINTAGE2D_INTR_FIFO_OVERFLOW,
                dev_info, VINTAGE2D_INTR);
}

void
start_device(pci_dev_info_t *dev_info)
{
    reset_device(dev_info);
    /* Enable interrupts */
    send_to_dev(VINTAGE2D_INTR_NOTIFY | VINTAGE2D_INTR_INVALID_CMD |
                VINTAGE2D_INTR_PAGE_FAULT | VINTAGE2D_INTR_CANVAS_OVERFLOW |
                VINTAGE2D_INTR_FIFO_OVERFLOW,
                dev_info, VINTAGE2D_INTR_ENABLE);
    /* Enable drawing and fetching commands */
    send_to_dev(VINTAGE2D_ENABLE_DRAW | VINTAGE2D_ENABLE_FETCH_CMD,
                dev_info, VINTAGE2D_ENABLE);
}

void
stop_device(pci_dev_info_t *dev_info)
{
    send_to_dev(0x0, dev_info, VINTAGE2D_ENABLE);
    send_to_dev(0x0, dev_info, VINTAGE2D_INTR_ENABLE);
    reset_device(dev_info);
}

void
reset_dev_info(pci_dev_info_t *pci_dev_info)
{
    pci_dev_info->pci_dev = NULL;
    pci_dev_info->char_dev = NULL;
    pci_dev_info->iomem = NULL;
    pci_dev_info->command_buf.buf.cpu_addr = NULL;
    pci_dev_info->command_buf.buf.dma_addr = 0;
    pci_dev_info->command_buf.cpu_write_ptr = NULL;
    pci_dev_info->command_buf.dma_write_ptr = 0;
    pci_dev_info->current_context = NULL;
}

// Utils for array of devices
// TODO: Synchronization in probe / remove?
void
init_pci_dev_info(pci_dev_info_t dev_info_arr[], unsigned int size,
                  unsigned int major, unsigned int first_minor)
{
    int i;
    for (i = 0; i < size; ++i) {
        dev_info_arr[i].device_number = i;
        dev_info_arr[i].minor = first_minor++;
        dev_info_arr[i].dev_number = MKDEV(major, dev_info_arr[i].minor);
        mutex_init(&dev_info_arr[i].mutex);
        init_waitqueue_head(&dev_info_arr[i].wait_queue);
        reset_dev_info(dev_info_arr + i);
    }
}

pci_dev_info_t *
get_first_free_device_info(pci_dev_info_t dev_info_arr[], unsigned int size)
{
    int i;
    for (i = 0; i < size; ++i) {
        if (dev_info_arr[i].pci_dev == NULL) {
            return dev_info_arr + i;
        }
    }
    return NULL;
}

pci_dev_info_t *
get_dev_info(pci_dev_info_t dev_info_arr[], unsigned int size,
             struct pci_dev *dev)
{
    int i;
    for (i = 0; i < size; ++i) {
        if (dev_info_arr[i].pci_dev == dev) {
            return dev_info_arr + i;
        }
    }
    return NULL;
}

pci_dev_info_t *
get_dev_info_by_minor(pci_dev_info_t dev_info_arr[], unsigned int size,
                      int minor)
{
    int i;
    for (i = 0; i < size; ++i) {
        if (dev_info_arr[i].minor == minor) {
            return dev_info_arr + i;
        }
    }
    return NULL;
}


// Command buffer utils

long *
get_last_command_addr(command_buf_t *buf)
{
    return ((long *) buf->buf.cpu_addr) + REAL_BUF_SIZE / COMMAND_SIZE;
}

void
init_command_buffer(pci_dev_info_t *pci_dev_info)
{
    long *last_command_addr;
    last_command_addr = get_last_command_addr(&pci_dev_info->command_buf);
    *last_command_addr = JUMP_TO(pci_dev_info->command_buf.buf.dma_addr);
    /* Initialize CMD_READ_PTR and CMD_WRITE_PTR */
    send_to_dev(pci_dev_info->command_buf.buf.dma_addr,
                pci_dev_info, VINTAGE2D_CMD_READ_PTR);
    send_to_dev(pci_dev_info->command_buf.buf.dma_addr,
                pci_dev_info, VINTAGE2D_CMD_WRITE_PTR);
    pci_dev_info->command_buf.cpu_write_ptr =
            (long *) pci_dev_info->command_buf.buf.cpu_addr;
    pci_dev_info->command_buf.dma_write_ptr =
            pci_dev_info->command_buf.buf.dma_addr;
}

void
wait_for_space(pci_dev_info_t *dev_info, unsigned int num_of_cmds)
{
    /* Wait until there is enough space in circular buffer */
    int cmd_read_ptr;
    wait_event(dev_info->wait_queue,
               ((cmd_read_ptr = read_from_dev(dev_info,
                                            VINTAGE2D_CMD_READ_PTR)) ==
                dev_info->command_buf.dma_write_ptr)
               ||
               (((int) (cmd_read_ptr - dev_info->command_buf.dma_write_ptr
                        + REAL_BUF_SIZE - 1)) % REAL_BUF_SIZE >=
                num_of_cmds * COMMAND_SIZE));
}

void
add_cmd_to_buf(pci_dev_info_t *dev_info, long cmd)
{
    command_buf_t *buf = &dev_info->command_buf;
    *buf->cpu_write_ptr = cmd;
    buf->cpu_write_ptr += 1;
    buf->dma_write_ptr += COMMAND_SIZE;
    if (buf->cpu_write_ptr == get_last_command_addr(buf)) {
        buf->cpu_write_ptr = (long *) buf->buf.cpu_addr;
        buf->dma_write_ptr = buf->buf.dma_addr;
    }
    send_to_dev(buf->dma_write_ptr, dev_info, VINTAGE2D_CMD_WRITE_PTR);
}

// File operations utils

void
sync_dev(pci_dev_info_t *dev_info)
{
    long current_flag, next_flag;

    /* Waits for the previous context to finish its job */
    if (dev_info->current_context == NULL) {
        /* Device already synchronized */
        return;
    }
    current_flag = read_from_dev(dev_info, VINTAGE2D_COUNTER);
    next_flag = current_flag == COUNTER_FLAG_0 ? COUNTER_FLAG_1 : COUNTER_FLAG_0;
    wait_for_space(dev_info, 1);
    add_cmd_to_buf(dev_info, VINTAGE2D_CMD_COUNTER(next_flag, 1));
    wait_event(dev_info->wait_queue,
               read_from_dev(dev_info, VINTAGE2D_COUNTER) == next_flag);
    dev_info->current_context = NULL;
}

void
change_context(pci_dev_info_t *dev_info, dev_context_info_t *context)
{
    sync_dev(dev_info);
    /* Reset TLB */
    send_to_dev(VINTAGE2D_RESET_TLB, dev_info, VINTAGE2D_RESET);
    /* Set page table */
    wait_for_space(dev_info, 2);
    add_cmd_to_buf(dev_info,
                   VINTAGE2D_CMD_CANVAS_PT(
                           context->canvas_page_info.page_table.dma_addr, 0));
    add_cmd_to_buf(dev_info,
                   VINTAGE2D_CMD_CANVAS_DIMS(context->canvas_width,
                                             context->canvas_height, 1));
    dev_info->current_context = context;
}

int
check_pos_cmd(long cmd, long x, long y, dev_context_info_t *dev_context)
{
    if (!REQUIRED_POS_CMD_BITS_ZERO(cmd) ||
            x < 0 ||
            x >= dev_context->canvas_width ||
            y < 0 ||
            y >= dev_context->canvas_height) {
        return -1;
    }
    return 0;
}

void
add_cmd_to_his(command_his_t *command_his, long cmd)
{
    command_his->prev_commands[command_his->ind] = cmd;
    command_his->ind = (command_his->ind + 1) % HIS_BUF_SIZE;
}

long
get_cmd_from_his(command_his_t *command_his, long cmd_type)
{
    int i;
    for (i = 0; i < HIS_BUF_SIZE; ++i) {
        if (V2D_CMD_TYPE(command_his->prev_commands[i]) == cmd_type) {
            return command_his->prev_commands[i];
        }
    }
    return -1;
}

void
clear_his(command_his_t *command_his)
{
    memset(&command_his->prev_commands, 0, sizeof(command_his->prev_commands));
    command_his->ind = 0;
}

int
handle_src_or_dst_pos_cmd(long cmd, pci_dev_info_t *dev_info)
{
    long pos_x, pos_y;
    pos_x = V2D_CMD_POS_X(cmd);
    pos_y = V2D_CMD_POS_Y(cmd);
    if (check_pos_cmd(cmd, pos_x, pos_y, dev_info->current_context) < 0) {
        return -1;
    }
    add_cmd_to_his(&dev_info->current_context->command_his, cmd);
    return 0;
}

int
handle_fill_color_cmd(long cmd, pci_dev_info_t *dev_info)
{
    if (!REQUIRED_FILL_COLOR_BITS_ZERO(cmd)) {
        return -1;
    }
    add_cmd_to_his(&dev_info->current_context->command_his, cmd);
    return 0;
}

int
handle_do_blit_cmd(long cmd, pci_dev_info_t *dev_info)
{
    long src_pos_cmd, dst_pos_cmd;
    long src_pos_x, src_pos_y, dst_pos_x, dst_pos_y, width, height;

    if (!REQUIRED_DRAW_CMD_BITS_ZERO(cmd)) {
        return -1;
    }

    src_pos_cmd = get_cmd_from_his(&dev_info->current_context->command_his,
                                   VINTAGE2D_CMD_TYPE_SRC_POS);
    dst_pos_cmd = get_cmd_from_his(&dev_info->current_context->command_his,
                                   VINTAGE2D_CMD_TYPE_DST_POS);
    if (src_pos_cmd == -1 || dst_pos_cmd == -1) {
        printk(KERN_WARNING "DO_BLIT should be preceded by SRC_POS and DST_POS\n");
        return -1;
    }
    src_pos_x = V2D_CMD_POS_X(src_pos_cmd);
    src_pos_y = V2D_CMD_POS_Y(src_pos_cmd);
    dst_pos_x = V2D_CMD_POS_X(dst_pos_cmd);
    dst_pos_y = V2D_CMD_POS_Y(dst_pos_cmd);
    width = V2D_CMD_WIDTH(cmd);
    height = V2D_CMD_HEIGHT(cmd);
    if (src_pos_x + width > dev_info->current_context->canvas_width ||
            dst_pos_x + width > dev_info->current_context->canvas_width ||
            src_pos_y + height > dev_info->current_context->canvas_height ||
            dst_pos_y + height > dev_info->current_context->canvas_height) {
        return -1;
    }
    wait_for_space(dev_info, 3);
    add_cmd_to_buf(dev_info, VINTAGE2D_CMD_DST_POS(dst_pos_x, dst_pos_y, 0));
    add_cmd_to_buf(dev_info, VINTAGE2D_CMD_SRC_POS(src_pos_x, src_pos_y, 0));
    add_cmd_to_buf(dev_info, VINTAGE2D_CMD_DO_BLIT(width, height, 1));
    clear_his(&dev_info->current_context->command_his);
    return 0;
}

int
handle_do_fill_cmd(long cmd, pci_dev_info_t *dev_info)
{
    long fill_color_cmd, dst_pos_cmd, dst_pos_x, dst_pos_y, width, height, color;
    if (!REQUIRED_DRAW_CMD_BITS_ZERO(cmd)) {
        return -1;
    }
    dst_pos_cmd = get_cmd_from_his(&dev_info->current_context->command_his,
                                   VINTAGE2D_CMD_TYPE_DST_POS);
    fill_color_cmd = get_cmd_from_his(&dev_info->current_context->command_his,
                                      VINTAGE2D_CMD_TYPE_FILL_COLOR);
    if (dst_pos_cmd == -1 || fill_color_cmd == -1) {
        printk(KERN_WARNING "DO_FILL should be preceded by DST_POS and FILL_COLOR\n");
        return -1;
    }
    dst_pos_x = V2D_CMD_POS_X(dst_pos_cmd);
    dst_pos_y = V2D_CMD_POS_Y(dst_pos_cmd);
    width = V2D_CMD_WIDTH(cmd);
    height = V2D_CMD_HEIGHT(cmd);
    if (dst_pos_x + width > dev_info->current_context->canvas_width ||
            dst_pos_y + height > dev_info->current_context->canvas_height) {
        return -1;
    }
    color = V2D_CMD_COLOR(fill_color_cmd);
    wait_for_space(dev_info, 3);
    add_cmd_to_buf(dev_info, VINTAGE2D_CMD_DST_POS(dst_pos_x, dst_pos_y, 0));
    add_cmd_to_buf(dev_info, VINTAGE2D_CMD_FILL_COLOR(color, 0));
    add_cmd_to_buf(dev_info, VINTAGE2D_CMD_DO_FILL(width, height, 1));
    clear_his(&dev_info->current_context->command_his);
    return 0;
}
// TODO: add __user
ssize_t
vintage_write(struct file *file, const char *buffer, size_t size, loff_t *offset)
{
    long current_command, i, err;
    dev_context_info_t *dev_context;
    pci_dev_info_t *dev_info;
    int (*handle_cmd_function) (long, pci_dev_info_t *);

    dev_context = (dev_context_info_t *) file->private_data;
    dev_info = dev_context->pci_dev_info;

    mutex_lock(&dev_context->mutex);
    if (!dev_context->was_ioctl || (size % COMMAND_SIZE) != 0) {
        mutex_unlock(&dev_context->mutex);
        return -EINVAL;
    }
    mutex_unlock(&dev_context->mutex);
    mutex_lock(&dev_info->mutex);
    if (dev_info->current_context != dev_context) {
        change_context(dev_info, dev_context);
    }
    for (i = 0; i < size; i += sizeof(long)) {
        if (copy_from_user(&current_command, buffer + i,
                sizeof(long)) != 0) {
            err = -EFAULT;
            goto write_error;
        }
        switch (V2D_CMD_TYPE(current_command)) {
            case VINTAGE2D_CMD_TYPE_SRC_POS:
            case V2D_CMD_TYPE_DST_POS:
                handle_cmd_function = handle_src_or_dst_pos_cmd;
                break;
            case V2D_CMD_TYPE_FILL_COLOR:
                handle_cmd_function = handle_fill_color_cmd;
                break;
            case V2D_CMD_TYPE_DO_BLIT:
                handle_cmd_function = handle_do_blit_cmd;
                break;
            case V2D_CMD_TYPE_DO_FILL:
                handle_cmd_function = handle_do_fill_cmd;
                break;
            default:
                err = -EINVAL;
                goto write_error;
        }
        if (handle_cmd_function(current_command, dev_info) < 0) {
            err = -EINVAL;
            goto write_error;
        }
    }
    mutex_unlock(&dev_info->mutex);
    return size;
write_error:
    mutex_unlock(&dev_info->mutex);
    return err;
}

void
cleanup_canvas_pages(struct device *device,
                     canvas_page_info_t *canvas_page_info,
                     unsigned long num_of_pages_to_cleanup)
{
    int i;
    dma_free_coherent(device, VINTAGE2D_PAGE_SIZE,
                      canvas_page_info->page_table.cpu_addr,
                      canvas_page_info->page_table.dma_addr);
    for (i = 0; i < num_of_pages_to_cleanup; ++i) {
        dma_free_coherent(device, VINTAGE2D_PAGE_SIZE,
                          canvas_page_info->pages[i].cpu_addr,
                          canvas_page_info->pages[i].dma_addr);
    }
    kfree(canvas_page_info->pages);
    memset((void *) canvas_page_info, 0, sizeof(canvas_page_info_t));
}

int
alloc_memory_for_canvas(uint16_t canvas_width, uint16_t canvas_height,
                        dev_context_info_t *dev_context)
{
    unsigned int i;
    unsigned long num_of_pages_to_alloc, canvas_size;
    unsigned long *page_entry_addr;
    vintage_mem_t *page_table;
    vintage_mem_t *current_page;
    canvas_page_info_t *canvas_page_info;
    struct device *device;

    canvas_size = canvas_width * canvas_height;
    device = &dev_context->pci_dev_info->pci_dev->dev;
    canvas_page_info = &dev_context->canvas_page_info;
    page_table = &canvas_page_info->page_table;
    page_table->cpu_addr = dma_zalloc_coherent(device, VINTAGE2D_PAGE_SIZE,
                                               &page_table->dma_addr,
                                               GFP_KERNEL);
    if (IS_ERR_OR_NULL(page_table->cpu_addr)) {
        printk(KERN_ERR "Failed to allocate memory for device's page table\n");
        return -1;
    }
    num_of_pages_to_alloc = DIV_ROUND_UP(canvas_size, VINTAGE2D_PAGE_SIZE);
    canvas_page_info->pages =
            (vintage_mem_t *) kzalloc(num_of_pages_to_alloc * sizeof(vintage_mem_t),
                                       GFP_KERNEL);
    page_entry_addr = (unsigned long *) page_table->cpu_addr;
    for (i = 0; i < num_of_pages_to_alloc; ++i) {
        current_page = canvas_page_info->pages + i;
        current_page->cpu_addr = dma_zalloc_coherent(device, VINTAGE2D_PAGE_SIZE,
                                                     &current_page->dma_addr,
                                                     GFP_KERNEL);
        if (IS_ERR_OR_NULL(current_page->cpu_addr)) {
            printk(KERN_ERR "Failed to allocate memory for device's page\n");
            cleanup_canvas_pages(device, canvas_page_info, i);
            return -1;
        }
        /* DMA address should be always aligned to frame size */
        WARN_ON((current_page->dma_addr & VINTAGE2D_PAGE_MASK) !=
                        current_page->dma_addr);
        page_entry_addr[i] =
                (current_page->dma_addr & VINTAGE2D_PAGE_MASK) | VINTAGE2D_PTE_VALID;
    }
    /* Allocation successful */
    canvas_page_info->num_of_pages = num_of_pages_to_alloc;
    dev_context->canvas_height = canvas_height;
    dev_context->canvas_width = canvas_width;
    return 0;
}

long
vintage_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct v2d_ioctl_set_dimensions dimensions;
    dev_context_info_t *dev_context;
    long err;

    if (cmd != V2D_IOCTL_SET_DIMENSIONS) {
        return -ENOTTY;
    }

    dev_context = (dev_context_info_t *) file->private_data;

    mutex_lock(&dev_context->mutex);

    if (dev_context->was_ioctl) {
        err = -EINVAL;
        goto ioctl_error;
    }
    if (copy_from_user((void *) &dimensions, (void *) arg,
            sizeof(struct v2d_ioctl_set_dimensions)) != 0) {
        printk(KERN_ERR "Copying from user space failed\n");
        err = -EFAULT;
        goto ioctl_error;
    }
    if (dimensions.width < MIN_WIDTH ||
            dimensions.width > MAX_WIDTH ||
            dimensions.height < MIN_HEIGHT ||
            dimensions.height > MAX_HEIGHT) {
        err = -EINVAL;
        goto ioctl_error;
    }
    if (alloc_memory_for_canvas(dimensions.width, dimensions.height,
                                dev_context) < 0) {
        err = -ENOMEM;
        goto ioctl_error;
    }
    /* ioctl successful */
    dev_context->was_ioctl = 1;
    mutex_unlock(&dev_context->mutex);
    return 0;
ioctl_error:
    mutex_unlock(&dev_context->mutex);
    return err;
}

int
vintage_mmap(struct file *file, struct vm_area_struct *vma)
{
    unsigned long i, num_of_mapped_pages, offset;
    dev_context_info_t *dev_context;
    vintage_mem_t *pages;

    dev_context = (dev_context_info_t *) file->private_data;
    if (!dev_context->was_ioctl) {
        return -EINVAL;
    }
    pages = dev_context->canvas_page_info.pages;
    /* vm_area_struct should always cover area aligned to page size */
    WARN_ON((vma->vm_end - vma->vm_start) % VINTAGE2D_PAGE_SIZE != 0);
    num_of_mapped_pages = (vma->vm_end - vma->vm_start) / VINTAGE2D_PAGE_SIZE;
    if (num_of_mapped_pages > dev_context->canvas_page_info.num_of_pages) {
        return -EINVAL;
    }
    for (i = 0; i < num_of_mapped_pages; ++i) {
        offset = i * VINTAGE2D_PAGE_SIZE;
        if (remap_pfn_range(vma, vma->vm_start + offset,
                            __pa(pages[i].cpu_addr) >> PAGE_SHIFT,
                            VINTAGE2D_PAGE_SIZE, vma->vm_page_prot) < 0) {
            return -EAGAIN;
        }
    }
    return 0;
}

int
vintage_open(struct inode *inode, struct file *file)
{
    pci_dev_info_t *dev_info;
    dev_context_info_t *dev_context;
    int minor;

    minor = iminor(inode);
    dev_info = get_dev_info_by_minor(dev_info_array, MAX_NUM_OF_DEVICES, minor);
    if (dev_info == NULL) {
        printk(KERN_ERR "Device with minor number %d not found\n", minor);
        return -ENODEV;
    }
    dev_context = kzalloc(sizeof(dev_context_info_t), GFP_KERNEL);
    if (IS_ERR_OR_NULL(dev_context)) {
        printk(KERN_ERR "Failed to allocate memory\n");
        return -ENOMEM;
    }
    dev_context->pci_dev_info = dev_info;
    mutex_init(&dev_context->mutex);
    file->private_data = (void *) dev_context;
    return 0;
}

int
vintage_release(struct inode *inode, struct file *file)
{
    dev_context_info_t *dev_context;
    /* Called always only once, no synchronization needed */
    dev_context = (dev_context_info_t *) file->private_data;
    if (dev_context->was_ioctl) {
        // TODO: fsync
        cleanup_canvas_pages(&dev_context->pci_dev_info->pci_dev->dev,
                             &dev_context->canvas_page_info,
                             dev_context->canvas_page_info.num_of_pages);
    }
    kfree(dev_context);
    return 0;
}

int
vintage_fsync(struct file *file, loff_t offset1, loff_t offset2, int datasync)
{
    dev_context_info_t *dev_context;
    dev_context = (dev_context_info_t *) file->private_data;

    if (!dev_context->was_ioctl) {
        return -EINVAL;
    }

    mutex_lock(&dev_context->pci_dev_info->mutex);
    if (dev_context->pci_dev_info->current_context == dev_context) {
        sync_dev(dev_context->pci_dev_info);
    }
    mutex_unlock(&dev_context->pci_dev_info->mutex);
    return 0;
}

// Device operations

irqreturn_t
irq_handler(int irq, void *dev)
{
    int interrupt;
    pci_dev_info_t *dev_info;

    dev_info = (pci_dev_info_t *) dev;
    if (dev_info->pci_dev->irq != irq) {
        printk(KERN_ERR "Vintage2D detected unexpected interrupt\n");
        return IRQ_HANDLED;
    }

    interrupt = read_from_dev(dev_info, VINTAGE2D_INTR);
    if (interrupt & VINTAGE2D_INTR_NOTIFY) {
        /* Either there is space in buffer or device finished its job */
        wake_up(&dev_info->wait_queue);
    }
    /* Neither of cases below should happen */
    if (interrupt & VINTAGE2D_INTR_INVALID_CMD) {
        printk(KERN_ERR "Vintage2D interrupt: invalid command\n");
    }
    if (interrupt & VINTAGE2D_INTR_PAGE_FAULT) {
        printk(KERN_ERR "Vintage2D interrupt: page fault\n");
    }
    if (interrupt & VINTAGE2D_INTR_CANVAS_OVERFLOW) {
        printk(KERN_ERR "Vintage2D interrupt: canvas overflow\n");
    }
    if (interrupt & VINTAGE2D_INTR_FIFO_OVERFLOW) {
        printk(KERN_ERR "Vintage2D interrupt: FIFO overflow\n");
    }
    /* Mark all interrupts as handled */
    send_to_dev(interrupt, dev_info, VINTAGE2D_INTR);
    return IRQ_HANDLED;
}

static int
vintage_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
    struct cdev *char_dev;
    struct device *device;
    pci_dev_info_t *pci_dev_info;
    void __iomem *iomem;
    void *cpu_addr;
    dma_addr_t dma_addr;
    int ret;

    printk(KERN_WARNING "Vintage probe\n");

    pci_dev_info = get_first_free_device_info(dev_info_array, MAX_NUM_OF_DEVICES);
    if (pci_dev_info == NULL) {
        printk(KERN_ERR "Failed to add new device\n");
        return -ENODEV;
    }

    char_dev = cdev_alloc();
    if (IS_ERR_OR_NULL(char_dev)) {
        printk(KERN_ERR "Failed to allocate char device\n");
        return -ENOMEM;
    }
    char_dev->owner = THIS_MODULE;
    char_dev->ops = &vintage_file_ops;
    ret = cdev_add(char_dev, pci_dev_info->dev_number, 1);
    if (ret < 0) {
        // TODO: Free char_dev?
        printk(KERN_ERR "Failed to add char device\n");
        return ret;
    }
    // TODO: call device_create before cdev_add?
    device = device_create(vintage_class, NULL, pci_dev_info->dev_number,
                           NULL, "v2d%d", pci_dev_info->device_number);
    if (IS_ERR_OR_NULL(device)) {
        printk(KERN_ERR "Failed to create device\n");
        ret = -ENODEV;
        goto device_create_failed;
    }

    if (!(pci_resource_flags(dev, 0) & IORESOURCE_MEM)) {
        printk(KERN_ERR "BAR0 is not an IO region\n");
        goto pci_request_regions_failed;
    }

    ret = pci_request_regions(dev, DRIVER_NAME);
    if (ret < 0) {
        printk(KERN_ERR "Failed to request BAR0\n");
        goto pci_request_regions_failed;
    }

    iomem = pci_iomap(dev, 0, MMIO_SIZE);
    if (IS_ERR_OR_NULL(iomem)) {
        printk(KERN_ERR "Failed to map BAR0\n");
        if (iomem == NULL) {
            ret = -ENOMEM;
        } else {
            ret = PTR_ERR(iomem);
        }
        goto pci_iomap_failed;
    }

    ret = request_irq(dev->irq, irq_handler, IRQF_SHARED, DRIVER_NAME,
                      (void *) pci_dev_info);
    if (ret < 0) {
        printk(KERN_ERR "Failed to request irq\n");
        goto request_irq_failed;
    }

    pci_set_master(dev);

    ret = pci_set_dma_mask(dev, DMA_BIT_MASK(32));
    if (ret < 0) {
        printk(KERN_ERR "Failed to set DMA mask\n");
        goto setup_dma_failed;
    }
    ret = pci_set_consistent_dma_mask(dev, DMA_BIT_MASK(32));
    if (ret < 0) {
        printk(KERN_ERR "Failed to set consistent DMA mask\n");
        goto setup_dma_failed;
    }

    /* Allocate memory for command buffer */
    cpu_addr = dma_zalloc_coherent(&dev->dev, COMMAND_BUF_SIZE, &dma_addr,
                                   GFP_KERNEL);
    if (IS_ERR_OR_NULL(cpu_addr)) {
        printk(KERN_ERR "Failed to allocate memory for device's command buffer\n");
        ret = -ENOMEM;
        goto setup_dma_failed;
    }

    ret = pci_enable_device(dev);
    if (ret < 0) {
        printk(KERN_ERR "Failed to enable device\n");
        goto enable_device_failed;
    }

    /* Device successfully added */
    pci_dev_info->pci_dev = dev;
    pci_dev_info->char_dev = char_dev;
    pci_dev_info->iomem = iomem;
    pci_dev_info->command_buf.buf.cpu_addr = cpu_addr;
    pci_dev_info->command_buf.buf.dma_addr = dma_addr;
    init_command_buffer(pci_dev_info);
    start_device(pci_dev_info);

    return 0;

enable_device_failed:
    dma_free_coherent(&dev->dev, COMMAND_BUF_SIZE, cpu_addr, dma_addr);
setup_dma_failed:
    pci_clear_master(dev);
    free_irq(dev->irq, (void *) pci_dev_info);
request_irq_failed:
    pci_iounmap(dev, iomem);
pci_iomap_failed:
    pci_release_regions(dev);
pci_request_regions_failed:
    device_destroy(vintage_class, pci_dev_info->dev_number);
device_create_failed:
    cdev_del(char_dev);
    return ret;
}

void
remove_device(pci_dev_info_t *pci_dev_info)
{
    if (pci_dev_info->pci_dev != NULL) {
        printk(KERN_DEBUG "Removing device\n");
        /* Disable interrupts, draw and fetching commands */
        stop_device(pci_dev_info);
        if (pci_is_enabled(pci_dev_info->pci_dev)) {
            pci_disable_device(pci_dev_info->pci_dev);
        }
        dma_free_coherent(&pci_dev_info->pci_dev->dev, COMMAND_BUF_SIZE,
                          pci_dev_info->command_buf.buf.cpu_addr,
                          pci_dev_info->command_buf.buf.dma_addr);
        pci_clear_master(pci_dev_info->pci_dev);
        free_irq(pci_dev_info->pci_dev->irq, (void *) pci_dev_info);
        pci_iounmap(pci_dev_info->pci_dev, pci_dev_info->iomem);
        pci_release_regions(pci_dev_info->pci_dev);
        device_destroy(vintage_class, pci_dev_info->dev_number);
        wake_up_all(&pci_dev_info->wait_queue);
    }
    if (pci_dev_info->char_dev != NULL) {
        cdev_del(pci_dev_info->char_dev);
    }
    reset_dev_info(pci_dev_info);
}

static void
vintage_remove(struct pci_dev *dev)
{
    pci_dev_info_t *pci_dev_info;
    printk(KERN_WARNING "Vintage remove\n");

    pci_dev_info = get_dev_info(dev_info_array, MAX_NUM_OF_DEVICES, dev);
    if (pci_dev_info == NULL) {
        printk(KERN_WARNING "Vintage remove: device not found in device table - "
                       "probably is already removed\n");
        if (pci_is_enabled(dev)) {
            pci_disable_device(dev);
        }
    } else {
        remove_device(pci_dev_info);
    }
}

static int
vintage_init_module(void)
{
    int ret;

    printk(KERN_ERR "Module init\n");

    /* allocate major numbers */
    ret = alloc_chrdev_region(&dev_number, 0, MAX_NUM_OF_DEVICES, DRIVER_NAME);
    if (ret < 0) {
        printk(KERN_ERR "Failed to allocate major number\n");
        return ret;
    }

    vintage_class = class_create(THIS_MODULE, DEVICE_CLASS_NAME);
    if (IS_ERR_OR_NULL(vintage_class)) {
        printk(KERN_ERR "Failed to create device class\n");
        ret = -EAGAIN;
        goto class_create_failed;
    }

    /* Init helper structures */
    major = MAJOR(dev_number);
    init_pci_dev_info(dev_info_array, MAX_NUM_OF_DEVICES, major, MINOR(dev_number));

    /* register pci driver */
    ret = pci_register_driver(&vintage_driver);
    if (ret < 0) {
        printk(KERN_ERR "Failed to register Vintage2D driver\n");
        goto pci_register_driver_failed;
    }

    return 0;

pci_register_driver_failed:
    class_destroy(vintage_class);
class_create_failed:
    unregister_chrdev_region(dev_number, MAX_NUM_OF_DEVICES);
    return ret;
}

static void
vintage_exit_module(void)
{
    int i;
    printk(KERN_WARNING "Module exit\n");

    /* unregister pci driver */
    pci_unregister_driver(&vintage_driver);

    /* Destroy device class */
    class_destroy(vintage_class);

    /* Remove devices */
    for(i = 0; i < MAX_NUM_OF_DEVICES; ++i) {
        remove_device(dev_info_array + i);
    }

    /* free major / minor number */
    unregister_chrdev_region(dev_number, MAX_NUM_OF_DEVICES);

    printk(KERN_DEBUG "Module exit end\n");
}

module_init(vintage_init_module);
module_exit(vintage_exit_module);