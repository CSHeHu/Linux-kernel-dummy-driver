#include "linux/gfp_types.h"
#include "linux/slab.h"
#include "linux/types.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "dummy"
#define MAJOR_NUM 240

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

	ret = register_chrdev(MAJOR_NUM, DEVICE_NAME, &dummy_fops);
	if (ret < 0) {
		pr_err("dummy: failed to register device\n");
		return ret;
	}

	pr_info("dummy: module loaded\n");
	pr_info("dummy: create device node with: mknod /dev/%s c %d 0\n", DEVICE_NAME, MAJOR_NUM);
	return 0;
}

static void __exit dummy_exit(void)
{
	unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
	pr_info("dummy: module unloaded\n");
}

module_init(dummy_init);
module_exit(dummy_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("You");
MODULE_DESCRIPTION("Simple dummy driver with /dev interface");
