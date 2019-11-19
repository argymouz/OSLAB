/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-crypto device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	
	// this is the way iterators are implemented in kernel C
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len, num_out, num_in;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int *syscall_type;
	int *host_fd;
	unsigned long flags;
	struct scatterlist syscall_type_sg, host_fd_sg, *sg[2];

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;
	host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = -1;

	crof = NULL;
	
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	num_out = 0;
	num_in = 0;
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sg[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sg[num_out + num_in++] = &host_fd_sg;
	
	spin_lock_irqsave(&crdev->lock, flags);
	ret = virtqueue_add_sgs(crdev->vq, sg, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	if (ret < 0) {
		spin_unlock_irqrestore(&crdev->lock, flags);
		debug("Could not add buffers to the vq.");
		goto fail;
	}
	virtqueue_kick(crdev->vq);
		
	/**
	 * Wait for the host to process our data.
	 **/
	while (virtqueue_get_buf(crdev->vq, &len) == NULL); // busy-wait loop
	spin_unlock_irqrestore(&crdev->lock, flags);

	/* If host failed to open() return -ENODEV. */
	debug("Backend returned file descriptor %d", *host_fd);
	if (*host_fd < 0) ret = -ENODEV;
	crof->host_fd = *host_fd;

fail:
//crof MUST remain
//	kfree(crof);
	kfree(syscall_type);
	kfree(host_fd);
	debug("Leaving with ret = %d", ret);
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int *syscall_type;
	unsigned int num_out, len;
	struct scatterlist syscall_type_sg, host_fd_sg, *sg[2];
	unsigned long flags;
	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;

	/**
	 * Send data to the host.
	 **/
	num_out = 0;
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sg[num_out++] = &syscall_type_sg;
	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
	sg[num_out++] = &host_fd_sg;
	spin_lock_irqsave(&crdev->lock, flags);
	ret = virtqueue_add_sgs(crdev->vq, sg, num_out, 0, &syscall_type_sg, GFP_ATOMIC);
	if (ret < 0) {
		spin_unlock_irqrestore(&crdev->lock, flags);
		debug("Could not add buffers to the vq.");
		goto fail;
	}
	virtqueue_kick(crdev->vq);

	/**
	 * Wait for the host to process our data.
	 **/
	while (virtqueue_get_buf(crdev->vq, &len) == NULL); // busy-wait loop
	spin_unlock_irqrestore(&crdev->lock, flags);
fail:
	kfree(crof);
	kfree(syscall_type);
	debug("Leaving");
	return ret;
}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	long ret = 0;
	int err;
	int *host_ret;
	uint32_t *ses_id;
	struct session_op *sess;
	struct crypt_op *cryp;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist sess_id_sg,syscall_type_sg, cmd_sg, session_sg, host_fd_sg, ret_sg, ses_id_sg, 
		cryp_src_sg, cryp_dst_sg, cryp_iv_sg, cryp_op_sg, seskey_sg,
	                   *sgs[8];
	unsigned int num_out, num_in, len, *cmd_ptr;
	unsigned long flags;
	unsigned char *ses_key, *src, *dst=NULL, *iv;
	unsigned int *syscall_type;

	printk(KERN_CRIT "Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_IOCTL;
	host_ret = kzalloc(sizeof(*host_ret), GFP_KERNEL);
	cmd_ptr = kzalloc(sizeof(*cmd_ptr), GFP_KERNEL);
	ses_id = kzalloc(sizeof(*ses_id), GFP_KERNEL);
	src=NULL;
	dst=NULL;
	iv=NULL;
	ses_key=NULL;
	*cmd_ptr = cmd;

	num_out = 0;
	num_in = 0;

	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	
	sg_init_one(&host_fd_sg,&crof->host_fd,sizeof(crof->host_fd));
	sgs[num_out++]=&host_fd_sg;	

	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (!sess) {
		return -ENOMEM;
	}

	cryp = kzalloc(sizeof(*cryp), GFP_KERNEL);
	if (!cryp) {
		return -ENOMEM;
	}

	switch (cmd) {
	case CIOCGSESSION:
		debug("CIOCGSESSION");
		sg_init_one(&cmd_sg, cmd_ptr, sizeof(*cmd_ptr));
		sgs[num_out++] = &cmd_sg;		
		if (copy_from_user(sess, (struct session_op*) arg, sizeof(struct session_op))){
			debug("copy_from_user");
			return -EFAULT;
		}
		ses_key = kzalloc(sess->keylen*sizeof(char), GFP_KERNEL);
		if (!ses_key) {
			return -ENOMEM;
		}
		if(copy_from_user(ses_key, sess->key, sizeof(char)*sess->keylen)){
			debug("copy_from_user");
			return -EFAULT;
		}
		sg_init_one(&seskey_sg, ses_key, sizeof(char)*sess->keylen);
		sgs[num_out++] = &seskey_sg;
		
		sg_init_one(&session_sg, sess, sizeof(*sess));
		sgs[num_out + num_in++] = &session_sg;
		
		sg_init_one(&ret_sg, host_ret, sizeof(*host_ret));
		sgs[num_out + num_in++] = &ret_sg;

		break;

	case CIOCFSESSION:
		debug("CIOCFSESSION");
		sg_init_one(&cmd_sg, cmd_ptr, sizeof(*cmd_ptr));
		sgs[num_out++] = &cmd_sg;

		if(copy_from_user(ses_id, (uint32_t*)arg, sizeof(*ses_id))){
			debug("copy_from_user");
			return -EFAULT;
		}
 		sg_init_one(&sess_id_sg, ses_id, sizeof(*ses_id));
		sgs[num_out++] = &sess_id_sg;
		sg_init_one(&ret_sg, host_ret, sizeof(host_ret));
		sgs[num_out + num_in++] = &ret_sg;
		break;

	case CIOCCRYPT:
		debug("CIOCCRYPT");
		sg_init_one(&cmd_sg, cmd_ptr, sizeof(*cmd_ptr));
		sgs[num_out++] = &cmd_sg;
		if(copy_from_user(cryp, (struct crypt_op*)arg, sizeof( struct crypt_op))){
			debug("copy_from_user");
			return -EFAULT;
		}

		sg_init_one(&cryp_op_sg, cryp, sizeof(*cryp));
		sgs[num_out++] = &cryp_op_sg;

		src = kzalloc(cryp->len*sizeof(char), GFP_KERNEL);
		if (!src) {
			return -ENOMEM;
		}

		if(copy_from_user(src, cryp->src, cryp->len*sizeof(char))){
			debug("copy_from_user");
			return -EFAULT;
		}

		sg_init_one(&cryp_src_sg, src, cryp->len*sizeof(char));
		sgs[num_out++] = &cryp_src_sg;

		iv = kzalloc(16*sizeof(char), GFP_KERNEL);
		if (!iv) {
			return -ENOMEM;
		}

		if(copy_from_user(iv, cryp->iv, 16*sizeof(char))){
			debug("copy_from_user");
			return -EFAULT;
		}	

		sg_init_one(&cryp_iv_sg, iv, cryp->len*sizeof(char));
		sgs[num_out++] = &cryp_iv_sg;


		dst = kzalloc(cryp->len*sizeof(char), GFP_KERNEL);
		if (!dst) {
			return -ENOMEM;
		}
		
		sg_init_one(&cryp_dst_sg, dst, cryp->len*sizeof(char));
		sgs[num_out + num_in++] = &cryp_dst_sg;

		sg_init_one(&ret_sg, host_ret, sizeof(host_ret));
		sgs[num_out + num_in++] = &ret_sg;
		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}

	spin_lock_irqsave(&crdev->lock, flags);

	err = virtqueue_add_sgs(vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	if (err < 0) {
                spin_unlock_irqrestore(&crdev->lock, flags);
                debug("Could not add buffers to the vq.");
                return -EINVAL;		
	}
	printk(KERN_CRIT "about to notify backend\n");
	virtqueue_kick(vq);
	printk(KERN_CRIT "backend has been notified");
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;
	printk(KERN_CRIT "backend has sent us data");
	spin_unlock_irqrestore(&crdev->lock,flags);
	
	switch(cmd){
	case CIOCGSESSION:
		debug("CIOCGSESSION");
		if((*host_ret<0)||(copy_to_user((struct session_op*)arg, sess,sizeof(struct session_op)))){
			debug("CIOCGSESSION");
			return -1;
		}
		break;
	case CIOCFSESSION:
		debug("CIOCFSESSION");
		if((*host_ret<0)){
			debug("CIOCFSESSION");
			return -1;
		}
		break;
	case CIOCCRYPT:
		debug("CIOCCRYPT");
		if((*host_ret<0)||(copy_to_user(((struct crypt_op*) arg)->dst, dst, cryp->len*sizeof(char)))){
			debug("CIOCCRYPT, with %d", err);
			return -1;
		}
		break;
	}

	kfree(syscall_type);
	kfree(host_ret);
	kfree(cmd_ptr);
	kfree(ses_id);
	kfree(sess);
	kfree(cryp);
	kfree(ses_key);
	kfree(src);
	kfree(dst);
	kfree(iv);
	debug("Leaving");

	return *host_ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
