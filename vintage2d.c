#include <linux/cdev.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>
#include "vintage2d.h"


MODULE_LICENSE("GPL");

/******************** Defines ****************************/

#define MAX_NUM_OF_DEVICES 256
#define DEVICE_NAME "Vintage2D"
#define DEVICE_CLASS_NAME "Vintage"

/******************** Typedefs ****************************/

typedef struct {
    int device_number;
    unsigned int minor;
    dev_t current_dev;
    struct pci_dev *pci_dev;
    struct cdev *char_dev;
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
    .name = DEVICE_NAME,
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

static int vintage_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
    struct cdev *char_dev;
    struct device *device;
    pci_dev_info_t *pci_dev_info;
    int ret;

    printk(KERN_DEBUG "Vintage probe\n");

    pci_dev_info = get_first_free_device_info();
    if (pci_dev_info == NULL) {
        printk(KERN_ERR "Can't add new device\n");
        // TODO: Which error?
        return -ENODEV;
    }

    char_dev = cdev_alloc();
    if (char_dev == NULL) {
        printk(KERN_ERR "Can't allocate char device\n");
        return -ENODEV;
    }
    char_dev->owner = THIS_MODULE;
    char_dev->ops = &vintage_file_ops;
    ret = cdev_add(char_dev, pci_dev_info->current_dev, 1);
    if (ret < 0) {
        printk(KERN_ERR "Can't add char device\n");
        return ret;
    }

    device = device_create(vintage_class, NULL, pci_dev_info->current_dev,
                           NULL, "v2d%d", pci_dev_info->device_number);
    if (IS_ERR_OR_NULL(device)) {
        printk(KERN_ERR "Can't create device\n");
        cdev_del(char_dev);
        // TODO: Which error?
        return -ENODEV;
    }

    ret = pci_enable_device(dev);
    if (ret < 0) {
        printk(KERN_ERR "Can't enable device\n");
        cdev_del(char_dev);
        device_destroy(vintage_class, pci_dev_info->current_dev);
        return ret;
    }

    // Device successfully added
    pci_dev_info->pci_dev = dev;
    pci_dev_info->char_dev = char_dev;
    return 0;
}

void remove_device(pci_dev_info_t *pci_dev_info)
{
    if (pci_dev_info->pci_dev != NULL) {
        pci_disable_device(pci_dev_info->pci_dev);
        pci_dev_info->pci_dev = NULL;
    }
    device_destroy(vintage_class, pci_dev_info->current_dev);
    if (pci_dev_info->char_dev != NULL) {
        cdev_del(pci_dev_info->char_dev);
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
    }
}

static int vintage_init_module(void)
{
    int ret;

    printk(KERN_DEBUG "Module init\n");

    /* allocate major numbers */
    ret = alloc_chrdev_region(&dev_number, 0, MAX_NUM_OF_DEVICES, DEVICE_NAME);
    if (ret < 0) {
        printk(KERN_ERR "Can't allocate major number\n");
        return ret;
    }

    vintage_class = class_create(THIS_MODULE, DEVICE_CLASS_NAME);
    if (IS_ERR_OR_NULL(vintage_class)) {
        printk(KERN_ERR "Can't create device class\n");
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
        printk(KERN_ERR "Can't register Vintage driver\n");
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

    printk(KERN_DEBUG "Module pci exit\n");
}

module_init(vintage_init_module);
module_exit(vintage_exit_module);
