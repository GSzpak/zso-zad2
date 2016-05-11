#include <linux/cdev.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/irqreturn.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include "vintage2d.h"


MODULE_LICENSE("GPL");

/******************** Defines ****************************/

#define MAX_NUM_OF_DEVICES 256
#define DRIVER_NAME "vintage2d-pci"
#define DEVICE_CLASS_NAME "Vintage"
#define MMIO_SIZE 4096
#define COMMAND_BUF_SIZE 65536

/******************** Typedefs ****************************/

typedef struct {
    int device_number;
    unsigned int minor;
    dev_t current_dev;
    struct pci_dev *pci_dev;
    struct cdev *char_dev;
    void __iomem *iomem;
} pci_dev_info_t;

typedef struct {
    pci_dev_info_t *pci_dev_info;
    unsigned char command_buf[COMMAND_BUF_SIZE];
    int was_ioctl;
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

void init_pci_dev_info(unsigned int first_minor)
{
    int i;
    for (i = 0; i < MAX_NUM_OF_DEVICES; ++i) {
        pci_dev_info[i].device_number = i;
        pci_dev_info[i].minor = first_minor++;
        pci_dev_info[i].current_dev = MKDEV(major, pci_dev_info[i].minor);
        pci_dev_info[i].pci_dev = NULL;
        pci_dev_info[i].char_dev = NULL;
        pci_dev_info[i].iomem = NULL;
    }
}

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


ssize_t vintage_write(struct file *file, const char __user *buffer,
                      size_t size, loff_t *offset)
{
    dev_context_info_t *dev_context = (dev_context_info_t *) file->private_data;
    if (!dev_context->was_ioctl) {
        return -EINVAL;
    }

    return 0;
}

long vintage_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    dev_context_info_t *dev_context = (dev_context_info_t *) file->private_data;
    if (dev_context->was_ioctl) {
        return -EINVAL;
    }
    return 0;
}

int vintage_mmap(struct file *file, struct vm_area_struct *vma)
{
    dev_context_info_t *dev_context = (dev_context_info_t *) file->private_data;
    if (!dev_context->was_ioctl) {
        return -EINVAL;
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
        return -ENOMEM;
    }
    minor = iminor(inode);
    dev_info = get_dev_info_by_minor(minor);
    dev_context_info->pci_dev_info = dev_info;
    file->private_data = (void *) dev_context_info;
    return 0;
}

int vintage_release(struct inode *inode, struct file *file)
{
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
    printk(KERN_WARNING "INTERRUPT! Irq: %d", irq);
    return IRQ_HANDLED;
}

// TODO: goto everywhere

static int vintage_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
    struct cdev *char_dev;
    struct device *device;
    pci_dev_info_t *pci_dev_info;
    void __iomem *iomem;
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
    ret = cdev_add(char_dev, pci_dev_info->current_dev, 1);
    if (ret < 0) {
        // TODO: Free char_dev?
        printk(KERN_ERR "Failed to add char device\n");
        return ret;
    }
    // TODO: call device_create before cdev_add?
    device = device_create(vintage_class, NULL, pci_dev_info->current_dev,
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
        printk(KERN_ERR "Failed to request irq");
        goto request_irq_failed;
    }

    ret = pci_enable_device(dev);
    if (ret < 0) {
        printk(KERN_ERR "Failed to enable device\n");
        goto enable_device_failed;
    }

    // Device successfully added
    pci_dev_info->pci_dev = dev;
    pci_dev_info->char_dev = char_dev;
    pci_dev_info->iomem = iomem;

    // FIXME: remove it
    printk(KERN_DEBUG "%p\n", iomem);

    return 0;

enable_device_failed:
    free_irq(dev->irq, iomem);
request_irq_failed:
    pci_iounmap(dev, iomem);
pci_iomap_failed:
    pci_release_regions(dev);
pci_request_regions_failed:
    device_destroy(vintage_class, pci_dev_info->current_dev);
device_create_failed:
    cdev_del(char_dev);
    return ret;
}

void remove_device(pci_dev_info_t *pci_dev_info)
{
    if (pci_dev_info->pci_dev != NULL) {
        printk(KERN_DEBUG "Removing device\n");
        pci_disable_device(pci_dev_info->pci_dev);
        printk(KERN_DEBUG "After disabling device\n");
        free_irq(pci_dev_info->pci_dev->irq, (void *) pci_dev_info);
        printk(KERN_DEBUG "After free_irq\n");
        if (pci_dev_info->iomem != NULL) {
            pci_iounmap(pci_dev_info->pci_dev, pci_dev_info->iomem);
            printk(KERN_DEBUG "After iounmap\n");
            pci_dev_info->iomem = NULL;
        }
        pci_release_regions(pci_dev_info->pci_dev);
        printk(KERN_DEBUG "After release_regions\n");
        pci_dev_info->pci_dev = NULL;
        device_destroy(vintage_class, pci_dev_info->current_dev);
        printk(KERN_DEBUG "After device_destroy\n");
    }
    if (pci_dev_info->char_dev != NULL) {
        cdev_del(pci_dev_info->char_dev);
        printk(KERN_DEBUG "After cdev_del\n");
        pci_dev_info->char_dev = NULL;
    }
}

static void vintage_remove(struct pci_dev *dev)
{
    pci_dev_info_t *pci_dev_info;
    printk(KERN_WARNING "vintage remove\n");

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
