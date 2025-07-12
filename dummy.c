#include "linux/cdev.h"
#include "linux/device.h"
#include "linux/err.h"
#include "linux/gfp_types.h"
#include "linux/slab.h"
#include "linux/types.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "dummy"
static dev_t dummy_devt;
static struct cdev dummy_cdev;
static struct class* dummy_class;
static struct device* dummy_dev;

static int dummy_open(struct inode *inode, struct file *file)
{
	pr_info("dummy: device opened\n");
	return 0;
}

static int dummy_release(struct inode *inode, struct file *file)
{
	pr_info("dummy: device closed\n");
	return 0;
}

static ssize_t dummy_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
	const char *msg = "Hello from dummy driver!\n";
	size_t msg_len = strlen(msg);

	if (*offset >= msg_len)
		return 0;

	if (len > msg_len - *offset)
		len = msg_len - *offset;

	if (copy_to_user(buf, msg + *offset, len))
		return -EFAULT;

	*offset += len;
	return len;
}

static ssize_t dummy_write(struct file *file, const char __user *buf, size_t len, loff_t *offset)
{
	char *msg = kmalloc(len + 1, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	if (copy_from_user(msg, buf, len)) {
		kfree(msg);
		return -EFAULT;
	}

	msg[len] = '\0';
	pr_info("dummy: received: %s\n", msg);

	*offset += len;

	kfree(msg);
	return len;
}

static const struct file_operations dummy_fops = {
	.owner = THIS_MODULE,
	.open = dummy_open,
	.release = dummy_release,
	.read = dummy_read,
	.write = dummy_write,
};

static int __init dummy_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&dummy_devt, 0, 1, DEVICE_NAME);
	if (ret) {
		pr_err("dummy: failed to register device\n");
		return ret;
	}

	cdev_init(&dummy_cdev, &dummy_fops);
	ret = cdev_add(&dummy_cdev, dummy_devt, 1);
	if (ret < 0) {
		pr_err("dummy: failed to add device\n");
		goto unregister_chrdev;
	}

	dummy_class = class_create(DEVICE_NAME);
	if (IS_ERR(dummy_class)) {
		pr_err("dummy: failed to create class\n");
		ret = PTR_ERR(dummy_class);
		goto del_cdev;
	}

	dummy_dev = device_create(dummy_class, NULL, dummy_devt, NULL, DEVICE_NAME);
	if (IS_ERR(dummy_dev)) {
		pr_err("dummy: failed to create device\n");
		ret = PTR_ERR(dummy_dev);
		goto destroy_class;
	}

	pr_info("dummy: module loaded\n");
	return 0;

destroy_class:
	class_destroy(dummy_class);
del_cdev:
	cdev_del(&dummy_cdev);
unregister_chrdev:
	unregister_chrdev_region(dummy_devt, 1);
	return ret;
}

static void __exit dummy_exit(void)
{
	device_destroy(dummy_class, dummy_devt);
	class_destroy(dummy_class);
	cdev_del(&dummy_cdev);
	unregister_chrdev_region(dummy_devt, 1);
	pr_info("dummy: module unloaded\n");
}

module_init(dummy_init);
module_exit(dummy_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("You");
MODULE_DESCRIPTION("Simple dummy driver with /dev interface");
