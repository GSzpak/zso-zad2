#include <asm/uaccess.h>
#include <linux/bug.h>
#include <linux/cdev.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/irqreturn.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include "vintage2d.h"
#include "v2d_ioctl.h"

// TODO: remove delay.h
MODULE_LICENSE("GPL");

/******************** Defines ****************************/

#define MAX_NUM_OF_DEVICES      256
#define DRIVER_NAME             "vintage2d-pci"
#define DEVICE_CLASS_NAME       "graphic"
#define MMIO_SIZE               4096
#define COMMAND_BUF_SIZE        65536
#define COMMAND_SIZE            4
#define MAX_WIDTH               2048
#define MAX_HEIGHT              2048
#define MIN_WIDTH               1
#define MIN_HEIGHT              1
#define REQUIRED_POS_CMD_BITS_ZERO(cmd)     (((cmd) & (1 << 19 | 1 << 31)) == 0)
#define REQUIRED_FILL_COLOR_BITS_ZERO(cmd)  (((cmd) & 0xffff0000) == 0)
#define REQUIRED_DRAW_CMD_BITS_ZERO(cmd)    (((cmd) & (1 << 19 | 1 << 31)) == 0)

/******************** Typedefs ****************************/

typedef struct {
    void *cpu_addr;
    dma_addr_t dma_addr;
} vintage_mem_t;

typedef struct {
    int device_number;
    unsigned int minor;
    dev_t dev_number;
    struct pci_dev *pci_dev;
    struct cdev *char_dev;
    void __iomem *iomem;
    vintage_mem_t command_buf;
    struct semaphore sem;
} pci_dev_info_t;

typedef struct {
    vintage_mem_t page_table;
    vintage_mem_t *pages;
    unsigned long num_of_pages;
} canvas_page_info_t;

typedef struct {
    long last_src_pos;
    long last_dst_pos;
    long last_fill_color;
} command_info_t;

typedef struct {
    pci_dev_info_t *pci_dev_info;
    int was_ioctl;
    canvas_page_info_t canvas_page_info;
    long canvas_height;
    long canvas_width;
    command_info_t command_info;
    struct semaphore sem;
} dev_context_info_t;


/******************** Function declarations ****************************/

static int vintage_probe(struct pci_dev *, const struct pci_device_id *);
static void vintage_remove(struct pci_dev *);
ssize_t vintage_write(struct file *, const char __user *, size_t, loff_t *);
long vintage_ioctl(struct file *, unsigned int, unsigned long);
int vintage_mmap(struct file *, struct vm_area_struct *);
int vintage_open(struct inode *, struct file *);
int vintage_release(struct inode *, struct file *);
int vintage_fsync(struct file *, loff_t, loff_t, int);

/******************** Global vaiables ****************************/

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
static pci_dev_info_t pci_dev_info[MAX_NUM_OF_DEVICES];
static struct class *vintage_class;

/******************** Definitions ****************************/


/******************** Utils ****************************/

void init_pci_dev_info(unsigned int first_minor)
{
    int i;
    for (i = 0; i < MAX_NUM_OF_DEVICES; ++i) {
        pci_dev_info[i].device_number = i;
        pci_dev_info[i].minor = first_minor++;
        pci_dev_info[i].dev_number = MKDEV(major, pci_dev_info[i].minor);
        pci_dev_info[i].pci_dev = NULL;
        pci_dev_info[i].char_dev = NULL;
        pci_dev_info[i].iomem = NULL;
        pci_dev_info->command_buf.cpu_addr = NULL;
        pci_dev_info->command_buf.dma_addr = 0;
    }
}
// TODO: Synchronization in probe / remove?
pci_dev_info_t *get_first_free_device_info(void) {
    int i;
    for (i = 0; i < MAX_NUM_OF_DEVICES; ++i) {
        if (pci_dev_info[i].pci_dev == NULL) {
            return pci_dev_info + i;
        }
    }
    return NULL;
}

pci_dev_info_t *get_dev_info(struct pci_dev *dev) {
    int i;
    for (i = 0; i < MAX_NUM_OF_DEVICES; ++i) {
        if (pci_dev_info[i].pci_dev == dev) {
            return pci_dev_info + i;
        }
    }
    return NULL;
}

pci_dev_info_t *get_dev_info_by_minor(int minor) {
    int i;
    for (i = 0; i < MAX_NUM_OF_DEVICES; ++i) {
        if (pci_dev_info[i].minor == minor) {
            return pci_dev_info + i;
        }
    }
    return NULL;
}

/******************** Write ****************************/

void send_cmd(long cmd, dev_context_info_t *dev_context)
{
    iowrite32(cmd, dev_context->pci_dev_info->iomem + VINTAGE2D_FIFO_SEND);
}

int check_pos_cmd(long cmd, long x, long y, dev_context_info_t *dev_context)
{
    printk(KERN_DEBUG "Check pos: x %d, y %d, width %d, height %d\n", x, y,
           dev_context->canvas_width, dev_context->canvas_height);
    if (!REQUIRED_POS_CMD_BITS_ZERO(cmd) ||
            x < 0 ||
            x >= dev_context->canvas_width ||
            y < 0 ||
            y >= dev_context->canvas_height) {
        return -1;
    }
    return 0;
}

int handle_src_pos_cmd(long cmd, dev_context_info_t *dev_context)
{
    long pos_x, pos_y;
    pos_x = V2D_CMD_POS_X(cmd);
    pos_y = V2D_CMD_POS_Y(cmd);
    if (check_pos_cmd(cmd, pos_x, pos_y, dev_context) < 0) {
        printk(KERN_DEBUG "Check_pos failed");
        return -1;
    }
    send_cmd(VINTAGE2D_CMD_SRC_POS(pos_x, pos_y, 1), dev_context);
    dev_context->command_info.last_src_pos = cmd;
    return 0;
}

int handle_dst_pos_cmd(long cmd, dev_context_info_t *dev_context)
{
    long pos_x, pos_y;
    pos_x = V2D_CMD_POS_X(cmd);
    pos_y = V2D_CMD_POS_Y(cmd);
    if (check_pos_cmd(cmd, pos_x, pos_y, dev_context) < 0) {
        return -1;
    }
    send_cmd(VINTAGE2D_CMD_DST_POS(pos_x, pos_y, 1), dev_context);
    dev_context->command_info.last_dst_pos = cmd;
    return 0;
}

int handle_fill_color_cmd(long cmd, dev_context_info_t *dev_context)
{
    long color;
    printk(KERN_DEBUG "color %p", cmd);
    if (!REQUIRED_FILL_COLOR_BITS_ZERO(cmd)) {
        printk(KERN_DEBUG "check color failed");
        return -1;
    }
    color = VINTAGE2D_CMD_COLOR(cmd);
    send_cmd(VINTAGE2D_CMD_FILL_COLOR(color, 1), dev_context);
    dev_context->command_info.last_fill_color = cmd;
    return 0;
}

int handle_do_blit_cmd(long cmd, dev_context_info_t * dev_context)
{
    long src_pos_x, src_pos_y, dst_pos_x, dst_pos_y, width, height;
    if (!REQUIRED_DRAW_CMD_BITS_ZERO(cmd) ||
            dev_context->command_info.last_src_pos == 0 ||
            dev_context->command_info.last_dst_pos == 0) {
        return -1;
    }
    src_pos_x = V2D_CMD_POS_X(dev_context->command_info.last_src_pos);
    src_pos_y = V2D_CMD_POS_Y(dev_context->command_info.last_src_pos);
    dst_pos_x = V2D_CMD_POS_X(dev_context->command_info.last_dst_pos);
    dst_pos_y = V2D_CMD_POS_Y(dev_context->command_info.last_dst_pos);
    width = V2D_CMD_WIDTH(cmd);
    height = V2D_CMD_HEIGHT(cmd);
    printk(KERN_DEBUG "Check blit: src_x %d, src_y %d, dst_x %d, dst_y %d, width %d, height %d\n",
           src_pos_x, src_pos_y, dst_pos_x, dst_pos_y, width, height);
    if (src_pos_x + width > dev_context->canvas_width ||
            dst_pos_x + width > dev_context->canvas_width ||
            src_pos_y + height > dev_context->canvas_height ||
            dst_pos_y + height > dev_context->canvas_height) {
        return -1;
    }
    send_cmd(VINTAGE2D_CMD_DO_BLIT(width, height, 1), dev_context);
    dev_context->command_info.last_src_pos = 0;
    dev_context->command_info.last_dst_pos = 0;
    return 0;
}

int handle_do_fill_cmd(long cmd, dev_context_info_t * dev_context)
{
    long dst_pos_x, dst_pos_y, width, height;
    if (!REQUIRED_DRAW_CMD_BITS_ZERO(cmd) ||
            dev_context->command_info.last_fill_color == 0 ||
            dev_context->command_info.last_dst_pos == 0) {
        return -1;
    }
    dst_pos_x = V2D_CMD_POS_X(dev_context->command_info.last_dst_pos);
    dst_pos_y = V2D_CMD_POS_Y(dev_context->command_info.last_dst_pos);
    width = V2D_CMD_WIDTH(cmd);
    height = V2D_CMD_HEIGHT(cmd);
    if (dst_pos_x + width > dev_context->canvas_width ||
            dst_pos_y + height > dev_context->canvas_height) {
        return -1;
    }
    send_cmd(VINTAGE2D_CMD_DO_FILL(width, height, 1), dev_context);
    dev_context->command_info.last_src_pos = 0;
    dev_context->command_info.last_dst_pos = 0;
    return 0;
}

ssize_t vintage_write(struct file *file, const char __user *buffer,
                      size_t size, loff_t *offset)
{
    long current_command, i;
    dev_context_info_t *dev_context;
    int (*handle_cmd_function) (long, dev_context_info_t *);

    dev_context = (dev_context_info_t *) file->private_data;
    if (!dev_context->was_ioctl || size % COMMAND_SIZE != 0) {
        printk(KERN_DEBUG "invalid command\n");
        return -EINVAL;
    }
    send_cmd(VINTAGE2D_CMD_CANVAS_PT(dev_context->canvas_page_info.page_table.dma_addr, 1),
             dev_context);
    send_cmd(VINTAGE2D_CMD_CANVAS_DIMS(dev_context->canvas_width, dev_context->canvas_height, 1),
             dev_context);
    for (i = 0; i < size; i += sizeof(unsigned long)) {
        if (copy_from_user(&current_command, buffer + i,
                sizeof(unsigned long)) != 0) {
            printk(KERN_DEBUG "Write efault\n");
            return -EFAULT;
        }
        switch (V2D_CMD_TYPE(current_command)) {
            case VINTAGE2D_CMD_TYPE_SRC_POS:
                printk(KERN_DEBUG "src pos\n");
                handle_cmd_function = handle_src_pos_cmd;
                break;
            case V2D_CMD_TYPE_DST_POS:
                printk(KERN_DEBUG "dst pos\n");
                handle_cmd_function = handle_dst_pos_cmd;
                break;
            case V2D_CMD_TYPE_FILL_COLOR:
                printk(KERN_DEBUG "fill\n");
                handle_cmd_function = handle_fill_color_cmd;
                break;
            case V2D_CMD_TYPE_DO_BLIT:
                printk(KERN_DEBUG "do blit\n");
                handle_cmd_function = handle_do_blit_cmd;
                break;
            case V2D_CMD_TYPE_DO_FILL:
                printk(KERN_DEBUG "do fill\n");
                handle_cmd_function = handle_do_fill_cmd;
                break;
            default:
                return -EINVAL;
        }
        if (handle_cmd_function(current_command, dev_context) < 0) {
            printk(KERN_DEBUG "Invalid command\n");
            return -EINVAL;
        }
    }
    printk(KERN_DEBUG "Success %d\n", i);
    return i;
}

/******************** ioctl & alloc ****************************/

void cleanup_canvas_pages(struct device *device,
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

int alloc_memory_for_canvas(uint16_t canvas_width, uint16_t canvas_height,
                            dev_context_info_t *dev_context)
{
    unsigned int i;
    unsigned long num_of_pages_to_alloc, canvas_size;
    unsigned long *page_entry_addr;
    vintage_mem_t *page_table;
    vintage_mem_t *current_page;
    canvas_page_info_t *canvas_page_info;
    struct device *device;

    printk(KERN_WARNING "Height: %d, width: %d\n", canvas_height, canvas_width);

    canvas_size = canvas_width * canvas_height;
    device = &dev_context->pci_dev_info->pci_dev->dev;
    canvas_page_info = &dev_context->canvas_page_info;
    page_table = &canvas_page_info->page_table;
    page_table->cpu_addr = dma_zalloc_coherent(device, VINTAGE2D_PAGE_SIZE,
                                               &page_table->dma_addr,
                                               GFP_KERNEL);
    if (IS_ERR_OR_NULL(page_table->cpu_addr)) {
        printk(KERN_ERR "Failed to allocate memory for device's page table\n");
        return -ENOMEM;
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
            return -ENOMEM;
        }
        // TODO: Remove check and '& PAGE_MASK'
        WARN_ON((current_page->dma_addr & PAGE_MASK) != current_page->dma_addr);
        page_entry_addr[i] = (current_page->dma_addr & PAGE_MASK) | VINTAGE2D_PTE_VALID;
    }
    /* Allocation successful */
    canvas_page_info->num_of_pages = num_of_pages_to_alloc;
    dev_context->canvas_height = canvas_height;
    dev_context->canvas_width = canvas_width;
    return 0;
}

long vintage_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct v2d_ioctl_set_dimensions dimensions;
    dev_context_info_t *dev_context;
    long ret;
    printk(KERN_WARNING "IOCTL\n");
    if (cmd != V2D_IOCTL_SET_DIMENSIONS) {
        return -ENOTTY;
    }
    dev_context = (dev_context_info_t *) file->private_data;
    if (dev_context->was_ioctl) {
        return -EINVAL;
    }
    if (copy_from_user((void *) &dimensions, (void *) arg,
            sizeof(struct v2d_ioctl_set_dimensions)) != 0) {
        printk(KERN_ERR "Copying from user space failed\n");
        return -EFAULT;
    }
    if (dimensions.width < MIN_WIDTH ||
            dimensions.width > MAX_WIDTH ||
            dimensions.height < MIN_HEIGHT ||
            dimensions.height > MAX_HEIGHT) {
        return -EINVAL;
    }
    ret = alloc_memory_for_canvas(dimensions.width, dimensions.height,
                                  dev_context);
    if (ret < 0) {
        return ret;
    }
    /* ioctl successful */
    dev_context->was_ioctl = 1;
    /* Enable drawing and fetching commands */
    iowrite32(VINTAGE2D_ENABLE_DRAW, pci_dev_info->iomem + VINTAGE2D_ENABLE);
    return 0;
}

int vintage_mmap(struct file *file, struct vm_area_struct *vma)
{
    unsigned long i, num_of_mmaped_pages, num_of_allocated_pages, offset;
    dev_context_info_t *dev_context;
    vintage_mem_t *pages;
    printk(KERN_WARNING "MMAP\n");
    dev_context = (dev_context_info_t *) file->private_data;
    if (!dev_context->was_ioctl) {
        return -EINVAL;
    }
    num_of_allocated_pages = dev_context->canvas_page_info.num_of_pages;
    pages = dev_context->canvas_page_info.pages;
    num_of_mmaped_pages = (vma->vm_end - vma->vm_start) / VINTAGE2D_PAGE_SIZE;
    if (num_of_mmaped_pages > num_of_allocated_pages) {
        return -EINVAL;
    }
    for (i = 0; i < num_of_allocated_pages; ++i) {
        offset = i * VINTAGE2D_PAGE_SIZE;
        if (remap_pfn_range(vma, vma->vm_start + offset,
                            __pa(pages[i].cpu_addr) >> PAGE_SHIFT,
                            VINTAGE2D_PAGE_SIZE, vma->vm_page_prot) < 0) {
            printk(KERN_ERR "Mmap failed\n");
            return -EAGAIN;
        }
    }
    return 0;
}

int vintage_open(struct inode *inode, struct file *file)
{
    pci_dev_info_t *dev_info;
    dev_context_info_t *dev_context_info;
    int minor;

    dev_context_info = kzalloc(sizeof(dev_context_info_t), GFP_KERNEL);
    if (IS_ERR_OR_NULL(dev_context_info)) {
        printk(KERN_ERR "Failed to allocate memory\n");
        return -ENOMEM;
    }
    minor = iminor(inode);
    dev_info = get_dev_info_by_minor(minor);
    if (dev_info == NULL) {
        printk(KERN_WARNING "Device with minor number %d not found\n", minor);
        return -EAGAIN;
    }
    dev_context_info->pci_dev_info = dev_info;
    file->private_data = (void *) dev_context_info;
    return 0;
}

int vintage_release(struct inode *inode, struct file *file)
{
    dev_context_info_t *dev_context_info;

    dev_context_info = (dev_context_info_t *) file->private_data;
    if (dev_context_info->was_ioctl) {
        cleanup_canvas_pages(&dev_context_info->pci_dev_info->pci_dev->dev,
                             &dev_context_info->canvas_page_info,
                             dev_context_info->canvas_page_info.num_of_pages);
    }
    kfree(file->private_data);
    return 0;
}

int vintage_fsync(struct file *file, loff_t offset1, loff_t offset2,
                  int datasync)
{
    return 0;
}

irqreturn_t irq_handler(int irq, void *dev)
{
    int interrupt;
    pci_dev_info_t *dev_info = (pci_dev_info_t *) dev;
    interrupt = ioread32(dev_info->iomem + VINTAGE2D_INTR);
    if (interrupt & VINTAGE2D_INTR_NOTIFY) {
        printk(KERN_DEBUG "INTERRUPT: notify");
    }
    if (interrupt & VINTAGE2D_INTR_INVALID_CMD) {
        printk(KERN_WARNING "INTERRUPT: invalid_cmd");
    }
    if (interrupt & VINTAGE2D_INTR_PAGE_FAULT) {
        printk(KERN_WARNING "INTERRUPT: page fault");
    }
    if (interrupt & VINTAGE2D_INTR_CANVAS_OVERFLOW) {
        printk(KERN_WARNING "INTERRUPT: canvas overflow");
    }
    if (interrupt & VINTAGE2D_INTR_FIFO_OVERFLOW) {
        printk(KERN_WARNING "INTERRUPT: fifo overflow");
    }
    iowrite32(interrupt, dev_info->iomem + VINTAGE2D_INTR);
    return IRQ_HANDLED;
}

void start_device(pci_dev_info_t *dev_info)
{
    /* Reset device */
    iowrite32(VINTAGE2D_RESET_DRAW | VINTAGE2D_RESET_FIFO | VINTAGE2D_RESET_TLB,
              pci_dev_info->iomem + VINTAGE2D_RESET);
    /* Reset interrupts */
    iowrite32(VINTAGE2D_INTR_NOTIFY | VINTAGE2D_INTR_INVALID_CMD |
              VINTAGE2D_INTR_PAGE_FAULT | VINTAGE2D_INTR_CANVAS_OVERFLOW |
              VINTAGE2D_INTR_FIFO_OVERFLOW,
              pci_dev_info->iomem + VINTAGE2D_INTR);
    //iowrite32(0x0, pci_dev_info->iomem + VINTAGE2D_CMD_READ_PTR);
    //iowrite32(0x0, pci_dev_info->iomem + VINTAGE2D_CMD_WRITE_PTR);

    /* Enable interrupts */
    iowrite32(VINTAGE2D_INTR_NOTIFY | VINTAGE2D_INTR_INVALID_CMD |
              VINTAGE2D_INTR_PAGE_FAULT | VINTAGE2D_INTR_CANVAS_OVERFLOW |
              VINTAGE2D_INTR_FIFO_OVERFLOW,
              pci_dev_info->iomem + VINTAGE2D_INTR_ENABLE);
    /* Enable drawing and fetching commands */
    //iowrite32(VINTAGE2D_ENABLE_DRAW, pci_dev_info->iomem + VINTAGE2D_ENABLE);
    // TODO: disable before release
}

static int vintage_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
    struct cdev *char_dev;
    struct device *device;
    pci_dev_info_t *pci_dev_info;
    void __iomem *iomem;
    void *cpu_addr;
    dma_addr_t dma_addr;
    int ret;

    printk(KERN_WARNING "Vintage probe\n");

    pci_dev_info = get_first_free_device_info();
    if (pci_dev_info == NULL) {
        printk(KERN_ERR "Failed to add new device\n");
        // TODO: Which error? (Check everywhere)
        return -ENODEV;
    }

    char_dev = cdev_alloc();
    if (IS_ERR_OR_NULL(char_dev)) {
        printk(KERN_ERR "Failed to allocate char device\n");
        return -ENODEV;
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
        // TODO: Which error?

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
    pci_dev_info->command_buf.cpu_addr = cpu_addr;
    pci_dev_info->command_buf.dma_addr = dma_addr;
    sema_init(&pci_dev_info->sem, 1);
    /* Start device */
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

void remove_device(pci_dev_info_t *pci_dev_info)
{
    if (pci_dev_info->pci_dev != NULL) {
        printk(KERN_DEBUG "Removing device\n");
        /* Disable interrupts, draw and fetching commands */
        iowrite32(0x0, pci_dev_info->iomem + VINTAGE2D_INTR_ENABLE);
        iowrite32(0x0, pci_dev_info->iomem + VINTAGE2D_ENABLE);
        pci_disable_device(pci_dev_info->pci_dev);
        dma_free_coherent(&pci_dev_info->pci_dev->dev, COMMAND_BUF_SIZE,
                          pci_dev_info->command_buf.cpu_addr,
                          pci_dev_info->command_buf.dma_addr);
        pci_dev_info->command_buf.cpu_addr = NULL;
        pci_dev_info->command_buf.dma_addr = 0;
        pci_clear_master(pci_dev_info->pci_dev);
        free_irq(pci_dev_info->pci_dev->irq, (void *) pci_dev_info);
        pci_iounmap(pci_dev_info->pci_dev, pci_dev_info->iomem);
        pci_dev_info->iomem = NULL;
        pci_release_regions(pci_dev_info->pci_dev);
        pci_dev_info->pci_dev = NULL;
        device_destroy(vintage_class, pci_dev_info->dev_number);
    }
    if (pci_dev_info->char_dev != NULL) {
        cdev_del(pci_dev_info->char_dev);
        pci_dev_info->char_dev = NULL;
    }
}

static void vintage_remove(struct pci_dev *dev)
{
    pci_dev_info_t *pci_dev_info;
    printk(KERN_WARNING "Vintage remove\n");

    pci_dev_info = get_dev_info(dev);
    if (pci_dev_info == NULL) {
        printk(KERN_WARNING "Device not found in device table\n");
        pci_disable_device(dev);
    } else {
        remove_device(pci_dev_info);
    }
}


static int vintage_init_module(void)
{
    int ret;

    printk(KERN_WARNING "Module init\n");

    /* allocate major numbers */
    ret = alloc_chrdev_region(&dev_number, 0, MAX_NUM_OF_DEVICES, DRIVER_NAME);
    if (ret < 0) {
        printk(KERN_ERR "Failed to allocate major number\n");
        return ret;
    }

    vintage_class = class_create(THIS_MODULE, DEVICE_CLASS_NAME);
    if (IS_ERR_OR_NULL(vintage_class)) {
        printk(KERN_ERR "Failed to create device class\n");
        // TODO: Which error?
        ret = -ENODEV;
        goto class_create_failed;
    }

    /* Init helper structures */
    major = MAJOR(dev_number);
    init_pci_dev_info(MINOR(dev_number));

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
    // TODO: unregister_chrdev_region(dev_number, 1) ?
    unregister_chrdev_region(dev_number, MAX_NUM_OF_DEVICES);
    return ret;
}

static void vintage_exit_module(void)
{
    int i;
    printk(KERN_WARNING "Module exit\n");

    /* unregister pci driver */
    pci_unregister_driver(&vintage_driver);

    /* Destroy device class */
    class_destroy(vintage_class);

    /* Remove devices */
    for(i = 0; i < MAX_NUM_OF_DEVICES; ++i) {
        remove_device(pci_dev_info + i);
    }

    /* free major/minor number */
    unregister_chrdev_region(dev_number, MAX_NUM_OF_DEVICES);

    printk(KERN_DEBUG "Module exit end\n");
}

module_init(vintage_init_module);
module_exit(vintage_exit_module);
