#include <linux/cdev.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/irqreturn.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/io.h>
#include <linux/pci.h>
#include "vintage2d.h"


MODULE_LICENSE("GPL");

/******************** Defines ****************************/

#define MAX_NUM_OF_DEVICES 256
#define DRIVER_NAME "vintage2d-pci"
#define DEVICE_CLASS_NAME "Vintage"
#define MMIO_SIZE 4096

/******************** Typedefs ****************************/

typedef struct {
    int device_number;
    unsigned int minor;
    dev_t current_dev;
    struct pci_dev *pci_dev;
    struct cdev *char_dev;
    void __iomem *iomem;
} pci_dev_info_t;

/******************** Function declarations ****************************/

static int vintage_probe(struct pci_dev *, const struct pci_device_id *);
static void vintage_remove(struct pci_dev *);
ssize_t vintage_read(struct file *, char __user *, size_t, loff_t *);
ssize_t vintage_write(struct file *, const char __user *, size_t, loff_t *);
int vintage_open(struct inode *, struct file *);
int vintage_release(struct inode *, struct file *);

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
    .read = vintage_read,
    .write = vintage_write,
    .open = vintage_open,
    .release = vintage_release,
};
static dev_t dev_number;
static unsigned int major;
static pci_dev_info_t pci_dev_info[MAX_NUM_OF_DEVICES];
static struct class *vintage_class;


/******************** Definitions ****************************/

ssize_t vintage_read(struct file *file, char __user *buffer,
                     size_t size, loff_t *offset)
{
    return 0;
}

ssize_t vintage_write(struct file *file, const char __user *buffer,
                      size_t size, loff_t *offset)
{
    return 0;
}

int vintage_open(struct inode *inode, struct file *file)
{
    return 0;
}

int vintage_release(struct inode *inode, struct file *file)
{
    return 0;
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

irqreturn_t irq_handler(int irq, void *dev)
{
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

    printk(KERN_DEBUG "Vintage probe\n");

    pci_dev_info = get_first_free_device_info();
    if (pci_dev_info == NULL) {
        printk(KERN_ERR "Failed to add new device\n");
        // TODO: Which error?
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

    device = device_create(vintage_class, NULL, pci_dev_info->current_dev,
                           NULL, "v2d%d", pci_dev_info->device_number);
    if (IS_ERR_OR_NULL(device)) {
        printk(KERN_ERR "Failed to create device\n");
        cdev_del(char_dev);
        // TODO: Which error?
        return -ENODEV;
    }

    if (!(pci_resource_flags(dev, 0) & IORESOURCE_MEM)) {
        printk(KERN_ERR "BAR0 is not an IO region\n");
        device_destroy(vintage_class, pci_dev_info->current_dev);
        cdev_del(char_dev);
        return ret;
    }

    ret = pci_request_regions(dev, DRIVER_NAME);
    if (ret < 0) {
        printk(KERN_ERR "Failed to request BAR0\n");
        device_destroy(vintage_class, pci_dev_info->current_dev);
        cdev_del(char_dev);
        return ret;
    }

    iomem = pci_iomap(dev, 0, MMIO_SIZE);
    if (IS_ERR_OR_NULL(iomem)) {
        printk(KERN_ERR "Failed to map BAR0\n");
        pci_release_regions(dev);
        device_destroy(vintage_class, pci_dev_info->current_dev);
        cdev_del(char_dev);
        return -ENODEV;
    }

    ret = request_irq(dev->irq, irq_handler, IRQF_SHARED, DRIVER_NAME,
                      (void *) pci_dev_info);
    if (ret < 0) {
        printk(KERN_ERR "Failed to request irq");
        pci_iounmap(dev, iomem);
        pci_release_regions(dev);
        device_destroy(vintage_class, pci_dev_info->current_dev);
        cdev_del(char_dev);
        return ret;
    }

    ret = pci_enable_device(dev);
    if (ret < 0) {
        printk(KERN_ERR "Failed to enable device\n");
        free_irq(dev->irq, iomem);
        pci_iounmap(dev, iomem);
        pci_release_regions(dev);
        device_destroy(vintage_class, pci_dev_info->current_dev);
        cdev_del(char_dev);
        return ret;
    }

    // Device successfully added
    pci_dev_info->pci_dev = dev;
    pci_dev_info->char_dev = char_dev;
    pci_dev_info->iomem = iomem;
    return 0;
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
    printk(KERN_DEBUG "vintage remove\n");

    pci_dev_info = get_dev_info(dev);
    if (pci_dev_info == NULL) {
        printk(KERN_WARNING "Device not found in device table\n");
        pci_disable_device(dev);
    } else {
        remove_device(pci_dev_info);
    }
}

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

static int vintage_init_module(void)
{
    int ret;

    printk(KERN_DEBUG "Module init\n");

    /* allocate major numbers */
    ret = alloc_chrdev_region(&dev_number, 0, MAX_NUM_OF_DEVICES, DRIVER_NAME);
    if (ret < 0) {
        printk(KERN_ERR "Failed to allocate major number\n");
        return ret;
    }

    vintage_class = class_create(THIS_MODULE, DEVICE_CLASS_NAME);
    if (IS_ERR_OR_NULL(vintage_class)) {
        printk(KERN_ERR "Failed to create device class\n");
        unregister_chrdev_region(dev_number, MAX_NUM_OF_DEVICES);
        // TODO: Which error?
        return -ENODEV;
    }

    /* Init helper structures */
    major = MAJOR(dev_number);
    init_pci_dev_info(MINOR(dev_number));

    /* register pci driver */
    ret = pci_register_driver(&vintage_driver);
    if (ret < 0) {
        // unregister_chrdev_region(dev_number, 1) ?
        unregister_chrdev_region(dev_number, MAX_NUM_OF_DEVICES);
        class_destroy(vintage_class);
        printk(KERN_ERR "Failed to register Vintage driver\n");
        return ret;
    }
    return 0;
}

static void vintage_exit_module(void)
{
    int i;
    printk(KERN_DEBUG "Module exit\n");

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
